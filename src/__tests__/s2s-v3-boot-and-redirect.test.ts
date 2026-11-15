/**
 * HTTP-mode boot check (no S2S secret of at least 32 characters, no start) and
 * fail-closed vendor redirects (addendum B).
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { installRedirectGuard } from "../redirect-guard.js";
import { dattoGet } from "../rmm-api.js";

describe("boot check", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env.MCP_TRANSPORT;
    delete process.env.CONDUIT_S2S_SECRET;
  });

  for (const [label, secret] of [["unset", undefined], ["empty", ""], ["31 characters", "x".repeat(31)]] as const) {
    it(`refuses to start in HTTP mode with the secret ${label}`, async () => {
      vi.resetModules();
      process.env.MCP_TRANSPORT = "http";
      process.env.MCP_HTTP_PORT = "47012";
      process.env.MCP_HTTP_HOST = "127.0.0.1";
      if (secret === undefined) delete process.env.CONDUIT_S2S_SECRET;
      else process.env.CONDUIT_S2S_SECRET = secret;
      const logs: string[] = [];
      vi.spyOn(console, "error").mockImplementation((...a: unknown[]) => { logs.push(a.map(String).join(" ")); });
      const exit = vi.spyOn(process, "exit").mockImplementation((() => { throw new Error("exit"); }) as never);
      await import("../index.js");
      await new Promise((r) => setTimeout(r, 100));
      expect(exit).toHaveBeenCalledWith(1);
      expect(logs.join("\n")).toContain("Refusing to start HTTP server");
      if (secret) expect(logs.join("\n")).not.toContain(secret);
    });
  }
});

describe("redirects fail closed", () => {
  it("the global guard rejects a 3xx from the server and never follows it", async () => {
    let followed = 0;
    const server = createServer((req, res) => {
      if (req.url === "/target") { followed++; res.end("secret place"); return; }
      res.writeHead(302, { Location: "/target" });
      res.end();
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    const port = (server.address() as AddressInfo).port;
    const realFetch = globalThis.fetch;
    try {
      installRedirectGuard();
      await expect(fetch(`http://127.0.0.1:${port}/start`, { headers: { Authorization: "Bearer t" } })).rejects.toThrow();
      expect(followed).toBe(0);
    } finally {
      globalThis.fetch = realFetch;
      server.closeAllConnections();
      server.close();
    }
  });

  it("an explicit caller choice is respected by the guard", async () => {
    const seen: (string | undefined)[] = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (_i: unknown, init?: RequestInit) => { seen.push(init?.redirect); return new Response("ok"); }) as typeof fetch;
    try {
      installRedirectGuard();
      await fetch("http://example.invalid/", { redirect: "manual" });
      await fetch("http://example.invalid/");
      expect(seen).toEqual(["manual", "error"]);
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it("rmm-api passes redirect: error on the token and API fetches", async () => {
    const seen: { url: string; redirect: string | undefined }[] = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (input: unknown, init?: RequestInit) => {
      const url = String(input);
      seen.push({ url, redirect: init?.redirect });
      if (url.includes("/auth/oauth/token")) {
        return new Response(JSON.stringify({ access_token: "a", token_type: "bearer", expires_in: 3600 }), { status: 200, headers: { "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "Content-Type": "application/json" } });
    }) as typeof fetch;
    try {
      await dattoGet({ apiKey: "redirect-test-key", apiSecretKey: "redirect-test-secret", platform: "concord" }, "/v2/account");
      expect(seen.length).toBeGreaterThanOrEqual(2);
      for (const s of seen) expect(s.redirect, s.url).toBe("error");
    } finally {
      globalThis.fetch = realFetch;
    }
  });
});
