/**
 * The vendored S2S v3 verifier (src/itsl/s2s-v3.ts) must stay byte-identical to
 * itsimplyltd/MCP-Gateway s2s/s2s-v3.ts and must pass the shared vectors.
 * Port of MCP-Gateway s2s/s2s-v3.test.ts (node:test) to vitest.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer, request as httpRequest } from "node:http";
import type { IncomingMessage } from "node:http";
import { Readable } from "node:stream";
import {
  NonceCache, RawBodyError, readRawBody, verifyV3, checkGatewayRequest, canonicalV3, parseV3Header,
  INGRESS_EXEMPT_HEADERS, assertRequireSignedHeaders, stripExemptHeaders, formatUnsignedHeaderReport,
  ReportRateLimiter, respondAndClose, effectiveMinVersion,
} from "../itsl/s2s-v3.js";

// sha256 of itsimplyltd/MCP-Gateway s2s/s2s-v3.ts (main at ff55ad8, PR 55).
const CANONICAL_S2S_V3_SHA256 = "3160ee243febcf990c4eb84f514c254a7d9a98592fa1d9b53888f1ad0dde11b0";

describe("vendored copy", () => {
  it("is byte-identical to the canonical file (hash pin)", () => {
    const bytes = readFileSync(new URL("../itsl/s2s-v3.ts", import.meta.url));
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(CANONICAL_S2S_V3_SHA256);
  });
});

const vectors = JSON.parse(readFileSync(new URL("./fixtures/s2s-v3-vectors.json", import.meta.url), "utf8"));
const secret: string = vectors.secret;

function args(c: any, cache: NonceCache) {
  return {
    method: c.method,
    rawTarget: c.rawTarget,
    body: Buffer.from(c.body, "utf8"),
    rawHeaders: c.rawHeaders,
    secret: c.secretOverride ?? secret,
    aud: c.aud,
    nowSeconds: c.nowSeconds,
    nonceCache: cache,
    headerRuleMode: c.headerRuleMode,
  };
}

describe("shared vectors", () => {
  for (const c of vectors.positive) {
    it(`positive: ${c.name}`, () => {
      expect(verifyV3(args(c, new NonceCache()))).toEqual({ ok: true, version: 3 });
    });
    if (!c.derivedFrom) {
      it(`positive canonical string is pinned: ${c.name}`, () => {
        const parsed = parseV3Header(c.header)!;
        const headerHashes: Record<string, string> = {};
        for (const [k, v] of Object.entries(c.signedHeaders)) headerHashes[k] = createHash("sha256").update(v as string).digest("hex");
        const canonical = canonicalV3({
          t: parsed.tRaw, n: parsed.n, aud: c.aud, method: c.method, path: c.rawTarget,
          bodySha256: createHash("sha256").update(c.body).digest("hex"), sh: parsed.sh, headerHashes,
        });
        expect(canonical).toBe(c.canonical);
        expect(canonical.endsWith("\n")).toBe(false);
        expect(canonical.split("\n")[0]).toBe("ITSL-S2S-v3");
      });
    }
  }

  for (const c of vectors.negative) {
    it(`negative: ${c.name} -> ${c.expect}`, () => {
      const cache = new NonceCache();
      if (c.replayOf) {
        const first = vectors.positive.find((p: any) => p.name === c.replayOf);
        expect(verifyV3(args(first, cache)).ok).toBe(true);
      }
      expect(verifyV3(args(c, cache))).toEqual({ ok: false, reason: c.expect });
    });
  }

  for (const c of vectors.check) {
    it(`checkGatewayRequest: ${c.name}`, () => {
      const r: any = checkGatewayRequest({
        ...args(c, new NonceCache()),
        floor: c.floor,
        minVersion: c.minVersion,
        verifyLegacy: () => c.legacyResult ?? 0,
      });
      expect(r.ok).toBe(c.expect.ok);
      expect(r.version).toBe(c.expect.version);
      if (!c.expect.ok) expect(r.reason).toBe(c.expect.reason);
      expect(r.unsignedHeaderNames).toEqual(c.expect.unsignedHeaderNames);
    });
  }

  for (const c of vectors.readRawBody) {
    it(`readRawBody: ${c.name}`, async () => {
      const req = Object.assign(Readable.from([Buffer.from(c.body)]), { headers: c.headers }) as unknown as IncomingMessage;
      if (c.expectStatus) {
        await expect(readRawBody(req)).rejects.toSatisfy((e: any) => e instanceof RawBodyError && e.status === c.expectStatus);
      } else {
        expect((await readRawBody(req)).toString()).toBe(c.body);
      }
    });
  }

  for (const c of vectors.requireSigned) {
    it(`requireSigned: ${c.name}`, () => {
      const base = vectors.positive.find((p: any) => p.name === c.from);
      const rawHeaders = [...base.rawHeaders, ...(c.extraRawHeaders ?? [])];
      const r: any = verifyV3({ ...args(base, new NonceCache()), rawHeaders, headerRuleMode: c.headerRuleMode, requireSignedHeaders: c.requireSignedHeaders });
      expect(r.ok).toBe(c.expect.ok);
      if (!r.ok) expect(r.reason).toBe(c.expect.reason);
    });
  }
});

describe("verifier behaviour", () => {
  it("readRawBody: over the limit is a 413 whether declared or streamed", async () => {
    const declared = Object.assign(Readable.from([Buffer.alloc(10)]), { headers: { "content-length": "10" } }) as unknown as IncomingMessage;
    await expect(readRawBody(declared, 5)).rejects.toSatisfy((e: any) => e.status === 413);
    const streamed = Object.assign(Readable.from([Buffer.alloc(4), Buffer.alloc(4)]), { headers: {} }) as unknown as IncomingMessage;
    await expect(readRawBody(streamed, 5)).rejects.toSatisfy((e: any) => e.status === 413);
  });

  it("nonce is recorded only after the HMAC verifies", () => {
    const cache = new NonceCache();
    const c = vectors.positive[1];
    expect(verifyV3(args({ ...c, body: c.body + " " }, cache)).ok).toBe(false);
    expect(cache.entries.size).toBe(0);
    expect(verifyV3(args(c, cache)).ok).toBe(true);
    expect(cache.entries.size).toBe(1);
  });

  it("nonce entry lives until its own t + 30 + 5", () => {
    const cache = new NonceCache();
    const n = "0".repeat(32);
    cache.add(n, 1000, 1000);
    expect(cache.has(n, 1034)).toBe(true);
    expect(cache.has(n, 1035)).toBe(false);
  });

  it("a full nonce cache refuses new requests (fails closed)", () => {
    const cache = new NonceCache(2);
    const c = vectors.positive[0];
    cache.add("a".repeat(32), c.t, c.t);
    cache.add("b".repeat(32), c.t, c.t);
    expect(verifyV3(args(c, cache))).toEqual({ ok: false, reason: "nonce-cache-full" });
  });

  it("the wrong secret never verifies", () => {
    const c = vectors.positive[0];
    expect(verifyV3({ ...args(c, new NonceCache()), secret: "vector-s2s-anothersecret0123456789abcdef" })).toEqual({ ok: false, reason: "hmac" });
  });

  it("exempt header list is the expected exact list", () => {
    expect(INGRESS_EXEMPT_HEADERS).toEqual(["x-request-id", "x-arr-ssl", "x-envoy-expected-rq-timeout-ms", "x-envoy-external-address", "x-forwarded-for", "x-forwarded-path", "x-forwarded-proto", "x-k8se-app-kind", "x-k8se-app-name", "x-k8se-app-namespace", "x-k8se-protocol", "x-ms-containerapp-name", "x-ms-containerapp-revision-name"]);
  });

  it("an exempt name may never be required to be signed", () => {
    for (const name of INGRESS_EXEMPT_HEADERS) expect(() => assertRequireSignedHeaders([name])).toThrow();
  });

  it("requireSignedHeaders: invalid or exempt names throw at configuration time", () => {
    for (const list of vectors.requireSignedConfigErrors) expect(() => assertRequireSignedHeaders(list)).toThrow(/requireSignedHeaders/);
    expect(() => assertRequireSignedHeaders(["x-datto-api-key", "x-datto-api-secret", "x-datto-platform"])).not.toThrow();
  });

  it("stripExemptHeaders removes exempt names from headers and rawHeaders, in place, and nothing else", () => {
    const req = {
      headers: { host: "h", "x-request-id": "a", "x-keep": "k" } as Record<string, unknown>,
      rawHeaders: ["Host", "h", "X-Request-Id", "a", "X-Keep", "k", "x-request-id", "b"],
    };
    const same = req.rawHeaders;
    stripExemptHeaders(req);
    expect(req.headers).toEqual({ host: "h", "x-keep": "k" });
    expect(req.rawHeaders).toEqual(["Host", "h", "X-Keep", "k"]);
    expect(req.rawHeaders).toBe(same);
  });

  it("formatUnsignedHeaderReport sanitises", () => {
    expect(formatUnsignedHeaderReport(["X-Foo", "x-bar"])).toEqual(["x-bar", "x-foo"]);
    expect(formatUnsignedHeaderReport(["x-a b", "x".repeat(65)])).toEqual(["invalid-name", "invalid-name"]);
    expect(formatUnsignedHeaderReport(Array.from({ length: 30 }, (_, i) => "x-h" + i)).length).toBe(20);
  });

  it("ReportRateLimiter: one emit per distinct key per 60 s, bounded memory", () => {
    const l = new ReportRateLimiter(3, 60);
    expect(l.shouldEmit(["b", "a"], 100)).toBe(true);
    expect(l.shouldEmit(["a", "b"], 120)).toBe(false);
    expect(l.shouldEmit(["a"], 120)).toBe(true);
    expect(l.shouldEmit(["a", "b"], 160)).toBe(true);
    for (let i = 0; i < 50; i++) l.shouldEmit(["x-" + i], 200);
    expect(l.last.size).toBeLessThanOrEqual(3);
  });

  it("effectiveMinVersion: max(floor, min), invalid counted as 3", () => {
    expect(effectiveMinVersion(1, 1)).toBe(1);
    expect(effectiveMinVersion(2, 1)).toBe(2);
    expect(effectiveMinVersion(1, 3)).toBe(3);
    expect(effectiveMinVersion(1, NaN)).toBe(3);
    expect(effectiveMinVersion(1, 0)).toBe(3);
    expect(effectiveMinVersion(1, 1.5)).toBe(3);
  });

  it("respondAndClose answers with Connection: close", async () => {
    const server = createServer((_req, res) => respondAndClose(res, 413, '{"error":"too_large"}'));
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    const port = (server.address() as { port: number }).port;
    const got = await new Promise<{ status: number; connection: string; body: string }>((resolve, reject) => {
      const rq = httpRequest({ host: "127.0.0.1", port, method: "POST", agent: false }, (res) => {
        let b = "";
        res.on("data", (d) => (b += d));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, connection: String(res.headers.connection), body: b }));
      });
      rq.on("error", reject);
      rq.write("x");
      rq.end();
    });
    server.close();
    expect(got).toEqual({ status: 413, connection: "close", body: '{"error":"too_large"}' });
  });
});
