/**
 * Coverage for compactUdf (src/mcp-server.ts), applied to every device
 * record datto_list_devices and datto_get_device return.
 *
 * Live sweep (4 Oct 2026) found every device record carries a `udf` object
 * with 300 keys (`udf1`-`udf300`), almost all null - about 2,500 tokens of
 * pure noise per device. compactUdf drops the null/empty-string entries so
 * only real UDF values (e.g. an RMM policy's note) survive.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { compactUdf } from "../mcp-server.js";
import worker from "../worker.js";

describe("compactUdf", () => {
  it("drops null and empty-string UDF keys, keeping only real values", () => {
    const udf: Record<string, string | null> = {};
    for (let i = 1; i <= 300; i++) udf[`udf${i}`] = null;
    udf.udf19 = "[Issues: 3] EDR: …";
    udf.udf42 = "some other note";
    udf.udf7 = ""; // empty string also dropped

    const device = { uid: "device-1", hostname: "HOST-1", udf };
    const result = compactUdf(device);

    expect(Object.keys(result.udf as object)).toEqual(["udf19", "udf42"]);
    expect((result.udf as Record<string, string>).udf19).toBe("[Issues: 3] EDR: …");
    expect((result.udf as Record<string, string>).udf42).toBe("some other note");
  });

  it("becomes {} when every UDF is null", () => {
    const udf: Record<string, null> = {};
    for (let i = 1; i <= 300; i++) udf[`udf${i}`] = null;

    const result = compactUdf({ uid: "device-1", udf });
    expect(result.udf).toEqual({});
  });

  it("passes a device without a `udf` field through unchanged", () => {
    const device = { uid: "device-1", hostname: "HOST-1" };
    const result = compactUdf(device);
    expect(result).toBe(device);
    expect(result).not.toHaveProperty("udf");
  });

  it("passes a device through unchanged if `udf` isn't an object", () => {
    const device = { uid: "device-1", udf: null as unknown };
    const result = compactUdf(device);
    expect(result).toBe(device);
  });
});

describe("datto_list_devices / datto_get_device integration", () => {
  const DATTO_HOST = "https://concord-api.centrastage.net";
  const ENV = { DATTO_API_KEY: "test-key", DATTO_API_SECRET: "test-secret" };
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  function bigUdf(nonNull: Record<string, string> = {}) {
    const udf: Record<string, string | null> = {};
    for (let i = 1; i <= 300; i++) udf[`udf${i}`] = null;
    Object.assign(udf, nonNull);
    return udf;
  }

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
          JSON.stringify({ access_token: "fake-token", token_type: "bearer", expires_in: 3600 }),
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

  it("datto_get_device strips null UDFs from the device it returns", async () => {
    stubFetch((url) => {
      if (url.includes("/v2/device/device-1")) {
        return jsonResponse({
          uid: "device-1",
          hostname: "HOST-1",
          udf: bigUdf({ udf19: "[Issues: 3] EDR: …" }),
        });
      }
      return undefined;
    });

    const res = await call("datto_get_device", { deviceUid: "device-1" });
    const body = (await res.json()) as {
      result?: { content?: { text?: string }[]; isError?: boolean };
    };
    // datto_get_device is wrapped in the untrusted-content marker.
    const text = body.result?.content?.[0]?.text ?? "{}";
    const inner = text
      .replace(/^<datto-data>\n/, "")
      .replace(/\n<\/datto-data>[\s\S]*$/, "");
    const device = JSON.parse(inner);

    expect(Object.keys(device.udf)).toEqual(["udf19"]);
  });

  it("datto_list_devices strips null UDFs from every device it returns", async () => {
    stubFetch((url) => {
      if (url.includes("/v2/account/devices")) {
        return jsonResponse({
          pageDetails: { count: 1, nextPageUrl: null },
          devices: [
            { uid: "device-1", hostname: "HOST-1", udf: bigUdf({ udf42: "note" }) },
          ],
        });
      }
      return undefined;
    });

    const res = await call("datto_list_devices", { max: 10 });
    const body = (await res.json()) as {
      result?: { content?: { text?: string }[]; isError?: boolean };
    };
    const text = body.result?.content?.[0]?.text ?? "[]";
    const inner = text
      .replace(/^<datto-data>\n/, "")
      .replace(/\n<\/datto-data>[\s\S]*$/, "");
    const { devices } = JSON.parse(inner);

    expect(Object.keys(devices[0].udf)).toEqual(["udf42"]);
  });
});
