/**
 * Coverage for datto_get_esxi_host_audit, which calls Datto RMM's
 * GET /v2/audit/esxihost/{deviceUid} directly via `dattoGet`.
 */
import { describe, it, expect, afterEach, vi } from "vitest";
import worker from "../worker.js";

const DATTO_HOST = "https://concord-api.centrastage.net";
const ENV = { DATTO_API_KEY: "test-key", DATTO_API_SECRET: "test-secret" };

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

async function call(name: string, args: Record<string, unknown>) {
  return worker.fetch(
    new Request("http://worker.local/mcp", {
      method: "POST",
      headers: {
        Accept: "application/json, text/event-stream",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name, arguments: args },
      }),
    }),
    ENV
  );
}

function stubFetch(handler: (url: string) => Response | undefined) {
  globalThis.fetch = vi.fn(async (input) => {
    const url = typeof input === "string" ? input : input.toString();
    if (url.startsWith(`${DATTO_HOST}/auth/oauth/token`)) {
      return new Response(
        JSON.stringify({
          access_token: "fake-token",
          token_type: "bearer",
          expires_in: 3600,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }
    const stubbed = handler(url);
    if (stubbed) return stubbed;
    throw new Error(`Unstubbed fetch in test: GET ${url}`);
  }) as typeof fetch;
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

describe("datto_get_esxi_host_audit", () => {
  it("returns the audit JSON as-is, wrapped in the untrusted-content marker", async () => {
    stubFetch((url) =>
      url.includes("/v2/audit/esxihost/")
        ? jsonResponse({ systemInfo: { vendor: "Dell" }, guests: [], nics: [] })
        : undefined
    );

    const res = await call("datto_get_esxi_host_audit", { deviceUid: "device-1" });
    const body = (await res.json()) as {
      result?: { content?: { text?: string }[]; isError?: boolean };
    };
    const text = body.result?.content?.[0]?.text ?? "";

    expect(body.result?.isError).toBeFalsy();
    expect(text.startsWith("<datto-data>\n")).toBe(true);
    expect(text).toContain('"vendor": "Dell"');
  });

  it("surfaces the documented 400 (wrong device class) as a clear error", async () => {
    stubFetch((url) =>
      url.includes("/v2/audit/esxihost/")
        ? new Response(
            JSON.stringify({ status: 400, error: "Bad Request" }),
            { status: 400, statusText: "Bad Request" }
          )
        : undefined
    );

    const res = await call("datto_get_esxi_host_audit", { deviceUid: "not-an-esxi-host" });
    const body = (await res.json()) as {
      result?: { content?: { text?: string }[]; isError?: boolean };
    };

    expect(body.result?.isError).toBe(true);
    expect(body.result?.content?.[0]?.text).toMatch(/400/);
  });
});
