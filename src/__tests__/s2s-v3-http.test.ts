/**
 * S2S v3 phase A through the real HTTP server (src/index.ts), no mocking of the
 * server. Two instances are started from fresh module state: one at the default
 * minimum (legacy v1 and v3 accepted, header rule in report mode) and one at
 * ITSL_S2S_MIN_VERSION=3. The signers in helpers/ are ports of cred-router's.
 */
import { describe, it, expect, vi, beforeAll } from "vitest";
import { connect } from "node:net";
import { legacyHeader, v3Header } from "./helpers/s2s-signers.js";

const SECRET = "http-test-s2s-secret-0123456789abcdef0123456789";
const AUD = "datto";
const PORT_DEFAULT = 47010;
const PORT_MIN3 = 47011;

const CREDS = {
  "x-datto-api-key": "test-api-key",
  "x-datto-api-secret": "test-api-secret",
  "x-datto-platform": "concord",
};
const LIST_TOOLS = JSON.stringify({ jsonrpc: "2.0", method: "tools/list", id: 1 });

const startupLogs: Record<number, string[]> = {};

async function startServer(port: number, minVersion: string | undefined): Promise<void> {
  vi.resetModules();
  process.env.MCP_TRANSPORT = "http";
  process.env.AUTH_MODE = "gateway";
  process.env.MCP_HTTP_PORT = String(port);
  process.env.MCP_HTTP_HOST = "127.0.0.1";
  process.env.CONDUIT_S2S_SECRET = SECRET;
  if (minVersion === undefined) delete process.env.ITSL_S2S_MIN_VERSION;
  else process.env.ITSL_S2S_MIN_VERSION = minVersion;
  const lines: string[] = [];
  startupLogs[port] = lines;
  const spy = vi.spyOn(console, "error").mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(" ")); });
  try {
    await import("../index.js");
    const deadline = Date.now() + 5000;
    for (;;) {
      try {
        if ((await fetch(`http://127.0.0.1:${port}/health`)).ok) break;
      } catch { /* not up yet */ }
      if (Date.now() > deadline) throw new Error("server did not start");
      await new Promise((r) => setTimeout(r, 50));
    }
  } finally {
    spy.mockRestore();
  }
}

function post(port: number, headers: Record<string, string>, body = LIST_TOOLS, path = "/mcp", method = "POST"): Promise<Response> {
  return fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...headers },
    body: method === "GET" ? undefined : body,
  });
}

const signedCreds = (extra: Record<string, string> = {}) => ({ ...CREDS, ...extra });

describe("default minimum (legacy v1 and v3 accepted)", () => {
  beforeAll(() => startServer(PORT_DEFAULT, undefined));

  it("logs the effective minimum version and the header rule mode at start-up, and no secret", () => {
    const line = startupLogs[PORT_DEFAULT].find((l) => l.includes("S2S v3 configuration"));
    expect(line).toBeTruthy();
    const parsed = JSON.parse(line!);
    expect(parsed.level).toBe("info");
    expect(parsed.effectiveMinVersion).toBe(1);
    expect(parsed.headerRule).toBe("report");
    expect(startupLogs[PORT_DEFAULT].join("\n")).not.toContain(SECRET);
  });

  it("accepts a legacy v1 header at the floor", async () => {
    const res = await post(PORT_DEFAULT, { "x-gateway-s2s": legacyHeader(SECRET), ...CREDS });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { result?: { tools?: unknown[] } };
    expect(Array.isArray(body.result?.tools)).toBe(true);
  });

  it("refuses a legacy header minted with the wrong secret, and a v2-shaped legacy header", async () => {
    expect((await post(PORT_DEFAULT, { "x-gateway-s2s": legacyHeader("wrong-secret-wrong-secret-wrong-secret-1"), ...CREDS })).status).toBe(401);
    const t = Math.floor(Date.now() / 1000);
    expect((await post(PORT_DEFAULT, { "x-gateway-s2s": `t=${t},v2=${"0".repeat(64)}`, ...CREDS })).status).toBe(401);
  });

  it("accepts a v3 header with the credential headers signed", async () => {
    const res = await post(PORT_DEFAULT, { "x-gateway-s2s": v3Header(SECRET, { aud: AUD, body: LIST_TOOLS, headers: signedCreds() }), ...CREDS });
    expect(res.status).toBe(200);
  });

  it("refuses a v3 header for the wrong audience, a tampered body and a replayed nonce", async () => {
    expect((await post(PORT_DEFAULT, { "x-gateway-s2s": v3Header(SECRET, { aud: "datto-bcdr", body: LIST_TOOLS, headers: signedCreds() }), ...CREDS })).status).toBe(401);
    expect((await post(PORT_DEFAULT, { "x-gateway-s2s": v3Header(SECRET, { aud: AUD, body: LIST_TOOLS + " ", headers: signedCreds() }), ...CREDS })).status).toBe(401);
    const header = v3Header(SECRET, { aud: AUD, body: LIST_TOOLS, headers: signedCreds() });
    expect((await post(PORT_DEFAULT, { "x-gateway-s2s": header, ...CREDS })).status).toBe(200);
    expect((await post(PORT_DEFAULT, { "x-gateway-s2s": header, ...CREDS })).status).toBe(401);
  });

  for (const missing of Object.keys(CREDS)) {
    it(`refuses v3 when ${missing} is present but not covered by the signature, even in report mode`, async () => {
      const signed = Object.fromEntries(Object.entries(CREDS).filter(([k]) => k !== missing));
      const res = await post(PORT_DEFAULT, { "x-gateway-s2s": v3Header(SECRET, { aud: AUD, body: LIST_TOOLS, headers: signed }), ...CREDS });
      expect(res.status).toBe(401);
    });
  }

  it("tolerates an unsigned non-required x- header in report mode", async () => {
    const res = await post(PORT_DEFAULT, { "x-gateway-s2s": v3Header(SECRET, { aud: AUD, body: LIST_TOOLS, headers: signedCreds() }), ...CREDS, "x-extra-thing": "1" });
    expect(res.status).toBe(200);
  });

  it("needs no S2S header to be refused: missing header is 401, and GET is 405 only after a valid header", async () => {
    expect((await post(PORT_DEFAULT, CREDS)).status).toBe(401);
    expect((await post(PORT_DEFAULT, { ...CREDS }, "", "/mcp", "GET")).status).toBe(401);
    expect((await post(PORT_DEFAULT, { "x-gateway-s2s": legacyHeader(SECRET), ...CREDS }, "", "/mcp", "GET")).status).toBe(405);
  });

  it("a verified request without credential headers is still refused by the backend", async () => {
    const res = await post(PORT_DEFAULT, { "x-gateway-s2s": legacyHeader(SECRET) });
    expect(res.status).toBe(401);
    expect(((await res.json()) as { error?: string }).error).toBe("Missing credentials");
  });

  it("returns 404 for unknown paths before auth", async () => {
    for (const path of ["/", "/mcp/", "/mcpx", "/admin", "/healthz", "/health/x"]) {
      expect((await post(PORT_DEFAULT, {}, "{}", path)).status, path).toBe(404);
    }
    expect((await fetch(`http://127.0.0.1:${PORT_DEFAULT}/health`)).status).toBe(200);
  });

  it("a socket aborted mid-body does not take the server down", async () => {
    const sock = connect(PORT_DEFAULT, "127.0.0.1");
    await new Promise<void>((r) => sock.once("connect", () => r()));
    sock.write(`POST /mcp HTTP/1.1\r\nHost: x\r\nX-Gateway-S2S: ${legacyHeader(SECRET)}\r\nContent-Length: 1000\r\n\r\n0123456789`);
    await new Promise((r) => setTimeout(r, 100));
    sock.destroy();
    await new Promise((r) => setTimeout(r, 150));
    expect((await fetch(`http://127.0.0.1:${PORT_DEFAULT}/health`)).status).toBe(200);
  });
});

describe("ITSL_S2S_MIN_VERSION=3", () => {
  beforeAll(() => startServer(PORT_MIN3, "3"));

  it("logs an effective minimum of 3 with the header rule enforced", () => {
    const parsed = JSON.parse(startupLogs[PORT_MIN3].find((l) => l.includes("S2S v3 configuration"))!);
    expect(parsed.effectiveMinVersion).toBe(3);
    expect(parsed.headerRule).toBe("enforced");
  });

  it("refuses a legacy header", async () => {
    expect((await post(PORT_MIN3, { "x-gateway-s2s": legacyHeader(SECRET), ...CREDS })).status).toBe(401);
  });

  it("accepts v3 with the credential headers signed", async () => {
    const res = await post(PORT_MIN3, { "x-gateway-s2s": v3Header(SECRET, { aud: AUD, body: LIST_TOOLS, headers: signedCreds() }), ...CREDS });
    expect(res.status).toBe(200);
  });

  it("refuses v3 with an unsigned credential header and with any other unsigned x- header", async () => {
    const partial = { "x-datto-api-secret": CREDS["x-datto-api-secret"], "x-datto-platform": CREDS["x-datto-platform"] };
    expect((await post(PORT_MIN3, { "x-gateway-s2s": v3Header(SECRET, { aud: AUD, body: LIST_TOOLS, headers: partial }), ...CREDS })).status).toBe(401);
    expect((await post(PORT_MIN3, { "x-gateway-s2s": v3Header(SECRET, { aud: AUD, body: LIST_TOOLS, headers: signedCreds() }), ...CREDS, "x-extra-thing": "1" })).status).toBe(401);
  });
});

