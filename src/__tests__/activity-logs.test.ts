/**
 * Coverage for datto_list_activity_logs, which calls Datto RMM's
 * GET /v2/activity-logs directly (not wrapped by the SDK) via `dattoGet`.
 *
 * Follows the same technique as component-tools.test.ts / job-tools.test.ts:
 * drive a real tools/call round-trip through the actual Worker `fetch`
 * entrypoint with only the network boundary (the Datto RMM host) stubbed.
 */
import { describe, it, expect, afterEach, vi } from "vitest";
import worker from "../worker.js";

const DATTO_HOST = "https://concord-api.centrastage.net";
const ENV = { DATTO_API_KEY: "test-key", DATTO_API_SECRET: "test-secret" };
const ACTIVITY_LOGS_PATH = "/api/v2/activity-logs";

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
  // datto_list_activity_logs is wrapped in the untrusted-content marker
  // (see untrusted-content.ts), so the raw JSON is sandwiched between
  // <datto-data> boundary lines rather than being the entire text.
  const text = body.result?.content?.[0]?.text ?? "{}";
  const inner = text
    .replace(/^<datto-data>\n/, "")
    .replace(/\n<\/datto-data>[\s\S]*$/, "");
  return JSON.parse(inner);
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

/**
 * Stubs the global fetch, always answering the OAuth token exchange, and
 * returns the array of every URL actually fetched (in order) - used both to
 * inspect the query string sent and to prove no request ever leaves the
 * platform host.
 */
function stubFetch(handler: (url: string) => Response | undefined): string[] {
  const seen: string[] = [];
  globalThis.fetch = vi.fn(async (input) => {
    const url = typeof input === "string" ? input : input.toString();
    seen.push(url);
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
  return seen;
}

function emptyPage(nextPageUrl: string | null = null) {
  return jsonResponse({
    pageDetails: { count: 0, prevPageUrl: null, nextPageUrl },
    activities: [],
  });
}

describe("datto_list_activity_logs", () => {
  it("defaults `from` to ~24 hours ago, in exact format with no milliseconds", async () => {
    let capturedUrl = "";
    stubFetch((url) => {
      if (url.includes(ACTIVITY_LOGS_PATH)) {
        capturedUrl = url;
        return emptyPage();
      }
      return undefined;
    });

    const before = Date.now();
    await call("datto_list_activity_logs", {});
    const after = Date.now();

    const from = new URL(capturedUrl).searchParams.get("from");
    expect(from).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);

    const fromMs = new Date(from!).getTime();
    const dayMs = 24 * 60 * 60 * 1000;
    expect(fromMs).toBeGreaterThanOrEqual(before - dayMs - 2000);
    expect(fromMs).toBeLessThanOrEqual(after - dayMs + 2000);
  });

  it("clamps size: 0 becomes 1, 500 becomes 250", async () => {
    const sizesSeen: (string | null)[] = [];
    stubFetch((url) => {
      if (url.includes(ACTIVITY_LOGS_PATH)) {
        sizesSeen.push(new URL(url).searchParams.get("size"));
        return emptyPage();
      }
      return undefined;
    });

    await call("datto_list_activity_logs", { size: 0 });
    await call("datto_list_activity_logs", { size: 500 });

    expect(sizesSeen).toEqual(["1", "250"]);
  });

  it("sends array filters comma-joined", async () => {
    let capturedUrl = "";
    stubFetch((url) => {
      if (url.includes(ACTIVITY_LOGS_PATH)) {
        capturedUrl = url;
        return emptyPage();
      }
      return undefined;
    });

    await call("datto_list_activity_logs", {
      categories: ["remote", "web.remote"],
      siteIds: [4, 8],
      entities: ["device", "user"],
    });

    const params = new URL(capturedUrl).searchParams;
    expect(params.get("categories")).toBe("remote,web.remote");
    expect(params.get("siteIds")).toBe("4,8");
    expect(params.get("entities")).toBe("device,user");
  });

  it("parses `details` into an object and converts the epoch date to ISO", async () => {
    stubFetch((url) => {
      if (url.includes(ACTIVITY_LOGS_PATH)) {
        return jsonResponse({
          pageDetails: { count: 1, prevPageUrl: null, nextPageUrl: null },
          activities: [
            {
              id: "1",
              entity: "DEVICE",
              category: "remote",
              action: "jrto",
              date: 1791106395,
              site: { id: 4, name: "Site A" },
              deviceId: 10,
              hostname: "HOST-1",
              user: { id: 1, userName: "jdoe", firstName: "J", lastName: "Doe" },
              details: '{"remote_session.type":"rdp","device.hostname":"HOST-1"}',
              hasStdOut: false,
              hasStdErr: false,
            },
          ],
        });
      }
      return undefined;
    });

    const res = await call("datto_list_activity_logs", {});
    const { activities } = await resultJson(res);

    expect(activities).toHaveLength(1);
    expect(activities[0].date).toBe(new Date(1791106395 * 1000).toISOString());
    // device.hostname repeats the top-level hostname column, so it is dropped.
    expect(activities[0].details).toEqual({
      "remote_session.type": "rdp",
    });
  });

  it("keeps `details` as the raw string when it fails to parse as JSON", async () => {
    stubFetch((url) => {
      if (url.includes(ACTIVITY_LOGS_PATH)) {
        return jsonResponse({
          pageDetails: { count: 1, prevPageUrl: null, nextPageUrl: null },
          activities: [
            {
              id: "1",
              entity: "USER",
              category: "account",
              action: "login",
              date: 1700000000,
              details: "not valid json {",
            },
          ],
        });
      }
      return undefined;
    });

    const res = await call("datto_list_activity_logs", {});
    const { activities } = await resultJson(res);
    expect(activities[0].details).toBe("not valid json {");
  });

  it("builds nextCursor from a nextPageUrl containing searchAfter", async () => {
    stubFetch((url) => {
      if (url.includes(ACTIVITY_LOGS_PATH)) {
        return jsonResponse({
          pageDetails: {
            count: 0,
            prevPageUrl: null,
            nextPageUrl: `${DATTO_HOST}/api/v2/activity-logs?searchAfter=1662554037000&searchAfter=60761aa3-d03e&page=next&size=100`,
          },
          activities: [],
        });
      }
      return undefined;
    });

    const res = await call("datto_list_activity_logs", {});
    const { nextCursor } = await resultJson(res);

    expect(nextCursor).toBeTruthy();
    const decoded = JSON.parse(Buffer.from(nextCursor, "base64url").toString("utf8"));
    expect(decoded).toEqual(["1662554037000", "60761aa3-d03e"]);
  });

  it("nextCursor is null when nextPageUrl is null", async () => {
    stubFetch((url) => (url.includes(ACTIVITY_LOGS_PATH) ? emptyPage(null) : undefined));

    const res = await call("datto_list_activity_logs", {});
    const { nextCursor } = await resultJson(res);
    expect(nextCursor).toBeNull();
  });

  it("a cursor round-trip sends searchAfter plus page=next, merged with the caller's own filters", async () => {
    let capturedUrl = "";
    stubFetch((url) => {
      if (url.includes(ACTIVITY_LOGS_PATH)) {
        capturedUrl = url;
        return emptyPage();
      }
      return undefined;
    });

    const cursor = Buffer.from(
      JSON.stringify(["1662554037000", "60761aa3-d03e"]),
      "utf8"
    ).toString("base64url");

    await call("datto_list_activity_logs", { cursor, categories: ["remote"] });

    const params = new URL(capturedUrl).searchParams;
    // Arrays (including searchAfter on the request side) are sent
    // comma-joined as a single query param, per the "query arrays are sent
    // comma-separated" convention used throughout this API.
    expect(params.get("searchAfter")).toBe("1662554037000,60761aa3-d03e");
    expect(params.get("page")).toBe("next");
    expect(params.get("categories")).toBe("remote");
  });

  it("never fetches a URL from a host other than the platform URL, even if nextPageUrl names another host", async () => {
    const seen = stubFetch((url) => {
      if (url.includes(ACTIVITY_LOGS_PATH)) {
        return jsonResponse({
          pageDetails: {
            count: 0,
            prevPageUrl: null,
            nextPageUrl: "https://evil.example.com/api/v2/activity-logs?searchAfter=xyz",
          },
          activities: [],
        });
      }
      return undefined;
    });

    const res = await call("datto_list_activity_logs", {});
    const { nextCursor } = await resultJson(res);

    // The malicious host's searchAfter value is still extracted safely from
    // the query string (parsing is fine) - it's just never fetched.
    expect(nextCursor).toBeTruthy();
    for (const url of seen) {
      expect(url.startsWith(DATTO_HOST)).toBe(true);
    }
  });
});
