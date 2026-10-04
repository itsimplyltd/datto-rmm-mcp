/**
 * datto_list_devices filters and the server-wide unknown-argument check.
 *
 * Found 2026-10-05: datto_list_devices accepted deviceType / deviceClass,
 * which it did not declare, and silently returned the head of the unfiltered
 * fleet cut to max ("no ESXi hosts" when there was one). The same happened
 * with deviceUid on datto_list_activity_logs, which returned other clients'
 * activity. Unknown arguments are now refused for every tool.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import worker from "../worker.js";
import { findUnknownArguments } from "../mcp-server.js";

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
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
    }),
    ENV
  );
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
}

function stubFetch(handler: (url: string) => Response | undefined): string[] {
  const seen: string[] = [];
  globalThis.fetch = vi.fn(async (input) => {
    const url = typeof input === "string" ? input : input.toString();
    if (url.startsWith(`${DATTO_HOST}/auth/oauth/token`)) {
      return jsonResponse({ access_token: "token", expires_in: 3600 });
    }
    seen.push(url);
    return handler(url) ?? new Response("not stubbed", { status: 500 });
  }) as typeof fetch;
  return seen;
}

async function result(res: Response): Promise<{ isError?: boolean; text: string }> {
  const body = (await res.json()) as { result?: { content?: { text?: string }[]; isError?: boolean } };
  return { isError: body.result?.isError, text: body.result?.content?.[0]?.text ?? "" };
}

function parseInner(text: string) {
  return JSON.parse(text.replace(/^<datto-data>\n/, "").replace(/\n<\/datto-data>[\s\S]*$/, ""));
}

function device(i: number, extra: Record<string, unknown> = {}) {
  return {
    uid: `dev-${i}`,
    hostname: `HOST-${i}`,
    siteName: "Site A",
    operatingSystem: "Windows Server 2019",
    deviceClass: "device",
    deviceType: { category: "Server", type: "Main System Chassis" },
    ...extra,
  };
}

describe("unknown arguments", () => {
  it("are refused before any API call, naming the accepted ones", async () => {
    const seen = stubFetch(() => undefined);
    const out = await result(await call("datto_list_activity_logs", { deviceUid: "dev-1" }));
    expect(out.isError).toBe(true);
    expect(out.text).toContain('"deviceUid"');
    expect(out.text).toContain("siteIds");
    expect(seen).toHaveLength(0);
  });

  it("findUnknownArguments passes known arguments and unknown tools", () => {
    const tools = [{ name: "t", inputSchema: { properties: { a: {} } } }];
    expect(findUnknownArguments(tools, "t", { a: 1 })).toBeNull();
    expect(findUnknownArguments(tools, "other", { z: 1 })).toBeNull();
    expect(findUnknownArguments(tools, "t", undefined)).toBeNull();
    expect(findUnknownArguments(tools, "t", { a: 1, b: 2 })).toContain('"b"');
  });
});

describe("datto_list_devices", () => {
  it("sends account-level filters to the API and reports the API's totalCount", async () => {
    const seen = stubFetch((url) =>
      url.includes("/v2/account/devices")
        ? jsonResponse({
            pageDetails: { totalCount: 91, nextPageUrl: `${DATTO_HOST}/api/v2/account/devices?page=1` },
            devices: [device(1), device(2)],
          })
        : undefined
    );
    const out = parseInner((await result(await call("datto_list_devices", { deviceType: "Server", max: 2 }))).text);
    expect(seen[0]).toContain("deviceType=Server");
    expect(seen).toHaveLength(1);
    expect(out.totalCount).toBe(91);
    expect(out.returned).toBe(2);
    expect(out.truncated).toBe(true);
  });

  it("filters deviceClass client-side across every page and counts exactly", async () => {
    const seen = stubFetch((url) => {
      if (!url.includes("/v2/account/devices")) return undefined;
      const page = Number(new URL(url).searchParams.get("page") ?? "0");
      return page === 0
        ? jsonResponse({
            pageDetails: { totalCount: 3, nextPageUrl: `${DATTO_HOST}/api/v2/account/devices?page=1` },
            devices: [device(1), device(2)],
          })
        : jsonResponse({
            pageDetails: { totalCount: 3, nextPageUrl: null },
            devices: [device(3, { deviceClass: "esxihost", deviceType: { category: "ESXi Host" } })],
          });
    });
    const out = parseInner((await result(await call("datto_list_devices", { deviceClass: "esxihost", max: 5 }))).text);
    expect(seen).toHaveLength(2);
    expect(out.totalCount).toBe(1);
    expect(out.returned).toBe(1);
    expect(out.truncated).toBe(false);
    expect(out.devices[0].uid).toBe("dev-3");
  });

  it("applies text filters client-side on the site endpoint, which has none", async () => {
    const seen = stubFetch((url) =>
      url.includes("/v2/site/site-1/devices")
        ? jsonResponse({
            pageDetails: { totalCount: 2, nextPageUrl: null },
            devices: [device(1), device(2, { deviceType: { category: "Laptop" } })],
          })
        : undefined
    );
    const out = parseInner(
      (await result(await call("datto_list_devices", { siteUid: "site-1", deviceType: "laptop" }))).text
    );
    expect(seen[0]).not.toContain("deviceType=");
    expect(out.totalCount).toBe(1);
    expect(out.devices[0].uid).toBe("dev-2");
  });
});
