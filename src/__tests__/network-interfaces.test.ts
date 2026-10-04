/**
 * Coverage for datto_list_site_network_interfaces, which calls Datto RMM's
 * GET /v2/site/{siteUid}/devices/network-interface directly via `dattoGet`.
 * The array key (`devices`, each with a `nics` array) comes straight from
 * the spec's response schema for this path, confirmed 4 Oct 2026.
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

async function resultJson(res: Response): Promise<any> {
  const body = (await res.json()) as {
    result?: { content?: { text?: string }[]; isError?: boolean };
  };
  expect(body.result?.isError).toBeFalsy();
  return JSON.parse(body.result?.content?.[0]?.text ?? "{}");
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

describe("datto_list_site_network_interfaces", () => {
  it("returns devices with their nics, from the real /devices/network-interface path", async () => {
    let capturedUrl = "";
    stubFetch((url) => {
      if (url.includes("/devices/network-interface")) {
        capturedUrl = url;
        return jsonResponse({
          pageDetails: { count: 1, totalCount: 1, prevPageUrl: null, nextPageUrl: null },
          devices: [
            {
              uid: "device-1",
              siteUid: "site-1",
              siteName: "Site A",
              hostname: "APP-HV-HOST06",
              intIpAddress: "10.0.0.5",
              extIpAddress: "203.0.113.5",
              nics: [
                { instance: "eth0", ipv4: "10.0.0.5", macAddress: "AA:BB:CC:DD:EE:FF", type: "ethernet" },
              ],
            },
          ],
        });
      }
      return undefined;
    });

    const res = await call("datto_list_site_network_interfaces", { siteUid: "site-1" });
    const { count, devices } = await resultJson(res);

    expect(capturedUrl).toContain("/v2/site/site-1/devices/network-interface");
    expect(count).toBe(1);
    expect(devices[0]).toMatchObject({
      uid: "device-1",
      hostname: "APP-HV-HOST06",
      intIpAddress: "10.0.0.5",
      extIpAddress: "203.0.113.5",
    });
    expect(devices[0].nics).toEqual([
      { instance: "eth0", ipv4: "10.0.0.5", macAddress: "AA:BB:CC:DD:EE:FF", type: "ethernet" },
    ]);
  });

  it("stops paginating once `max` devices are collected", async () => {
    const PAGE_1 = `${DATTO_HOST}/api/v2/site/site-1/devices/network-interface?max=1`;
    const PAGE_2 = `${DATTO_HOST}/api/v2/site/site-1/devices/network-interface?page=2`;

    stubFetch((url) => {
      if (url === PAGE_1) {
        return jsonResponse({
          pageDetails: { count: 1, prevPageUrl: null, nextPageUrl: PAGE_2 },
          devices: [{ uid: "d1", hostname: "H1", nics: [] }],
        });
      }
      return undefined; // PAGE_2 must never be fetched once max is hit
    });

    const res = await call("datto_list_site_network_interfaces", { siteUid: "site-1", max: 1 });
    const { count, devices } = await resultJson(res);

    expect(count).toBe(1);
    expect(devices[0].uid).toBe("d1");
  });
});
