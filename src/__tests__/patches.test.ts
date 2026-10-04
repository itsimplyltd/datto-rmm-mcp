/**
 * Coverage for src/patches.ts, specifically the 4 Oct 2026 fix to
 * datto_get_site_patches: it was calling the plural `/v2/sites/{siteUid}/patches`,
 * which 404s live ("No static resource v2/sites/..."). The real path is
 * singular: `/v2/site/{siteUid}/patches`.
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

describe("datto_get_site_patches", () => {
  it("calls the singular /v2/site/{siteUid}/patches path, not /v2/sites/", async () => {
    let capturedUrl = "";
    stubFetch((url) => {
      if (url.includes("/patches")) {
        capturedUrl = url;
        return jsonResponse({
          pageDetails: { count: 0, totalCount: 0, prevPageUrl: null, nextPageUrl: null },
          patches: [],
        });
      }
      return undefined;
    });

    const res = await call("datto_get_site_patches", { siteUid: "site-123" });
    const body = (await res.json()) as {
      result?: { content?: { text?: string }[]; isError?: boolean };
    };

    expect(body.result?.isError).toBeFalsy();
    expect(capturedUrl).toBe(`${DATTO_HOST}/api/v2/site/site-123/patches?page=0&max=250`);
    expect(capturedUrl).not.toContain("/v2/sites/");
  });

  it("surfaces the live 404 clearly if the wrong (plural) path were ever reintroduced", async () => {
    // Simulates what the real API actually returns for the bug this fixes,
    // to document the regression this test guards against.
    stubFetch((url) => {
      if (url.includes("/v2/sites/")) {
        return new Response("No static resource v2/sites/site-123/patches.", {
          status: 404,
          statusText: "Not Found",
        });
      }
      if (url.includes("/v2/site/site-123/patches")) {
        return jsonResponse({
          pageDetails: { count: 0, totalCount: 0, prevPageUrl: null, nextPageUrl: null },
          patches: [],
        });
      }
      return undefined;
    });

    const res = await call("datto_get_site_patches", { siteUid: "site-123" });
    const body = (await res.json()) as {
      result?: { content?: { text?: string }[]; isError?: boolean };
    };
    expect(body.result?.isError).toBeFalsy();
  });
});

describe("patch paging", () => {
  function patchRow(i: number) {
    return {
      patchId: `p-${i}`,
      title: `Patch ${i}`,
      description: "Long Microsoft boilerplate",
      severity: "IMPORTANT",
      installStatus: "NOT_APPROVED",
      totalDevices: 3,
    };
  }

  // Two pages, as the live API returns for a site with 372 patches: 250 then 122.
  function stubTwoPages(seen: string[]) {
    stubFetch((url) => {
      if (!url.includes("/patches")) return undefined;
      seen.push(url);
      const page = Number(new URL(url).searchParams.get("page") ?? "0");
      const rows = page === 0 ? 250 : 122;
      return jsonResponse({
        pageDetails: {
          count: rows,
          totalCount: 372,
          prevPageUrl: null,
          nextPageUrl:
            page === 0 ? "https://evil.example.com/api/v2/site/site-123/patches?max=250&page=1" : null,
        },
        patches: Array.from({ length: rows }, (_, i) => patchRow(page * 250 + i)),
      });
    });
  }

  async function resultJson(res: Response) {
    const body = (await res.json()) as { result?: { content?: { text?: string }[] } };
    const text = body.result?.content?.[0]?.text ?? "{}";
    return JSON.parse(text.replace(/^[\s\S]*?(\{)/, "$1").replace(/\}[^}]*$/, "}"));
  }

  it("follows every page and reports totalCount, without fetching nextPageUrl's host", async () => {
    const seen: string[] = [];
    stubTwoPages(seen);
    const res = await call("datto_get_site_patches", { siteUid: "site-123" });
    const out = await resultJson(res);
    expect(out.totalCount).toBe(372);
    expect(out.returned).toBe(372);
    expect(out.truncated).toBe(false);
    expect(seen).toHaveLength(2);
    expect(seen.every((u) => u.startsWith(DATTO_HOST))).toBe(true);
    expect(seen[1]).toContain("page=1");
  });

  it("marks the answer truncated when max cuts it short", async () => {
    stubTwoPages([]);
    const res = await call("datto_get_site_patches", { siteUid: "site-123", max: 100 });
    const out = await resultJson(res);
    expect(out.returned).toBe(100);
    expect(out.totalCount).toBe(372);
    expect(out.truncated).toBe(true);
  });

  it("omits patch descriptions on the site tool unless asked", async () => {
    stubTwoPages([]);
    const without = await resultJson(await call("datto_get_site_patches", { siteUid: "site-123", max: 1 }));
    expect(without.patches[0].description).toBeUndefined();
    stubTwoPages([]);
    const withDesc = await resultJson(
      await call("datto_get_site_patches", { siteUid: "site-123", max: 1, includeDescriptions: true })
    );
    expect(withDesc.patches[0].description).toBe("Long Microsoft boilerplate");
  });

  it("passes the installStatus filter through", async () => {
    const seen: string[] = [];
    stubTwoPages(seen);
    await call("datto_get_device_patches", { deviceUid: "dev-1", installStatus: "NOT_APPROVED", max: 1 });
    expect(seen[0]).toContain("installStatus=NOT_APPROVED");
  });
});
