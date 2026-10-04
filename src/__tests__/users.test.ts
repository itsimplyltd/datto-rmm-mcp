/**
 * Coverage for datto_list_users, which calls Datto RMM's
 * GET /v2/account/users directly via `dattoGet`.
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

describe("datto_list_users", () => {
  it("removes telephone but keeps every other field", async () => {
    stubFetch((url) => {
      if (url.includes("/v2/account/users")) {
        return jsonResponse({
          pageDetails: { count: 1, prevPageUrl: null, nextPageUrl: null },
          users: [
            {
              lastName: "Doe",
              firstName: "Jane",
              username: "jdoe",
              email: "jdoe@example.com",
              telephone: "+64 21 555 0100",
              status: "ACTIVE",
              created: "2024-01-15T09:00:00Z",
              lastAccess: "2026-10-01T08:30:00Z",
              disabled: false,
            },
          ],
        });
      }
      return undefined;
    });

    const res = await call("datto_list_users", {});
    const { count, users } = await resultJson(res);

    expect(count).toBe(1);
    expect(users).toHaveLength(1);
    expect(users[0]).not.toHaveProperty("telephone");
    expect(users[0]).toMatchObject({
      lastName: "Doe",
      firstName: "Jane",
      username: "jdoe",
      email: "jdoe@example.com",
      status: "ACTIVE",
      created: "2024-01-15T09:00:00Z",
      lastAccess: "2026-10-01T08:30:00Z",
      disabled: false,
    });
  });

  it("converts an epoch-number created/lastAccess to ISO", async () => {
    stubFetch((url) => {
      if (url.includes("/v2/account/users")) {
        return jsonResponse({
          pageDetails: { count: 1, prevPageUrl: null, nextPageUrl: null },
          users: [
            {
              username: "epoch-user",
              created: 1700000000,
              lastAccess: 1700000000,
              disabled: false,
            },
          ],
        });
      }
      return undefined;
    });

    const res = await call("datto_list_users", {});
    const { users } = await resultJson(res);

    expect(users[0].created).toBe(new Date(1700000000 * 1000).toISOString());
    expect(users[0].lastAccess).toBe(new Date(1700000000 * 1000).toISOString());
  });

  it("follows nextPageUrl via the query-string approach, capped at 1000", async () => {
    const PAGE_1 = `${DATTO_HOST}/api/v2/account/users`;
    const PAGE_2 = `${DATTO_HOST}/api/v2/account/users?page=2`;

    stubFetch((url) => {
      if (url === PAGE_1) {
        return jsonResponse({
          pageDetails: { count: 1, prevPageUrl: null, nextPageUrl: PAGE_2 },
          users: [{ username: "user-1", disabled: false }],
        });
      }
      if (url === PAGE_2) {
        return jsonResponse({
          pageDetails: { count: 1, prevPageUrl: PAGE_1, nextPageUrl: null },
          users: [{ username: "user-2", disabled: false }],
        });
      }
      return undefined;
    });

    const res = await call("datto_list_users", {});
    const { count, users } = await resultJson(res);

    expect(count).toBe(2);
    expect(users.map((u: { username?: string }) => u.username)).toEqual(["user-1", "user-2"]);
  });
});
