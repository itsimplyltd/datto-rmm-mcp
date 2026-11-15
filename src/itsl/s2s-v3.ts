// Copyright IT Simply Ltd. Canonical copy lives in itsimplyltd/MCP-Gateway s2s/s2s-v3.ts; vendored copies must stay byte-identical (CI hash pin).
//
// S2S v3 verifier (design: docs/superpowers/specs/2026-11-13-s2s-v3-design.md, 2.1 and 2.3).
//
//   X-Gateway-S2S: t=<unix s>,n=<32 hex>,sh=<a;b;c>,v3=<64 hex>
//
// Framework-agnostic: it takes the raw request target, the raw body bytes and
// req.rawHeaders, so it works behind any node:http handler. Only erasable
// TypeScript syntax is used (no enums, namespaces or parameter properties) so
// it runs under Node's type stripping AND drops into a normal TS build.
//
// Every failure returns a short machine reason. The CALLER answers 401 with a
// generic body and logs the reason; the reason must never reach the client.

import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';

export const S2S_SKEW_SECONDS = 30;
export const S2S_NONCE_MARGIN_SECONDS = 5;
export const S2S_HEADER = 'x-gateway-s2s';
export const S2S_REQUIRED_TARGET = '/mcp';

export type VerifyFailure = { ok: false; reason: string };

// Headers the platform ingress may add or rewrite, which are therefore never
// signed and never trip the header rule. EXACT lower-case names only: no prefix
// wildcards, anywhere. cred-router's signer (cred-router/src/s2sV3.js) holds a
// copy and a test keeps the two equal. Call stripExemptHeaders() after a
// successful verification so the application never sees an unsigned value.
export const INGRESS_EXEMPT_HEADERS: string[] = ['x-request-id', 'x-arr-ssl', 'x-envoy-expected-rq-timeout-ms', 'x-envoy-external-address', 'x-forwarded-for', 'x-forwarded-path', 'x-forwarded-proto', 'x-k8se-app-kind', 'x-k8se-app-name', 'x-k8se-app-namespace', 'x-k8se-protocol', 'x-ms-containerapp-name', 'x-ms-containerapp-revision-name'];

const nowSecondsDefault = (): number => Math.floor(Date.now() / 1000);

// Nonce cache. A nonce is kept until its own t + 30 s + 5 s (not a fixed time
// from first sight), the cache has a hard cap, and when full the caller must
// refuse (fail closed). Per process: a restart empties it (accepted limitation,
// bounded by the 30 s skew).
export class NonceCache {
  maxEntries: number;
  entries: Map<string, number>;
  nextPurge: number;
  constructor(maxEntries: number = 10000) {
    this.maxEntries = maxEntries;
    this.entries = new Map();
    this.nextPurge = 0;
  }
  purge(now: number = nowSecondsDefault(), force: boolean = false): void {
    if (!force && now < this.nextPurge) return;
    for (const [nonce, expires] of this.entries) {
      if (expires <= now) this.entries.delete(nonce);
    }
    this.nextPurge = now + 1;
  }
  has(nonce: string, now: number = nowSecondsDefault()): boolean {
    this.purge(now);
    const expires = this.entries.get(nonce);
    return expires !== undefined && expires > now;
  }
  add(nonce: string, t: number, now: number = nowSecondsDefault()): void {
    this.purge(now);
    this.entries.set(nonce, t + S2S_SKEW_SECONDS + S2S_NONCE_MARGIN_SECONDS);
  }
  isFull(now: number = nowSecondsDefault()): boolean {
    if (this.entries.size < this.maxEntries) return false;
    this.purge(now, true);
    return this.entries.size >= this.maxEntries;
  }
}

// Typed error from readRawBody. status is what the caller should answer.
export class RawBodyError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'RawBodyError';
    this.status = status;
    this.code = code;
  }
}

// Reads the exact request bytes. 413 above the limit (default 5 MB, matching
// cred-router), 415 for any content-encoding other than absent / identity: the
// signature covers the bytes on the wire, and a body that needs decoding is
// not something to hash and then hand to a parser.
// ON 413 / 415 THE CALLER MUST ANSWER WITH `Connection: close` AND DESTROY THE
// REQUEST (the unread body would otherwise sit on a keep-alive socket and be
// parsed as the next request). respondAndClose() below does exactly that.
export function readRawBody(req: IncomingMessage, limitBytes: number = 5 * 1024 * 1024): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const enc = req.headers['content-encoding'];
    const encValue = (Array.isArray(enc) ? enc.join(',') : enc ?? '').trim().toLowerCase();
    if (encValue !== '' && encValue !== 'identity') {
      reject(new RawBodyError(415, 'content-encoding', 'content-encoding not accepted'));
      return;
    }
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > limitBytes) {
      reject(new RawBodyError(413, 'too-large', 'body too large'));
      return;
    }
    const chunks: Buffer[] = [];
    let total = 0;
    let done = false;
    const finish = (fn: () => void): void => {
      if (done) return;
      done = true;
      req.removeListener('data', onData);
      req.removeListener('end', onEnd);
      req.removeListener('error', onError);
      fn();
    };
    const onData = (chunk: Buffer | string): void => {
      const buf = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
      total += buf.length;
      if (total > limitBytes) {
        finish(() => reject(new RawBodyError(413, 'too-large', 'body too large')));
        return;
      }
      chunks.push(buf);
    };
    const onEnd = (): void => finish(() => resolve(Buffer.concat(chunks)));
    const onError = (err: Error): void => finish(() => reject(err));
    req.on('data', onData);
    req.on('end', onEnd);
    req.on('error', onError);
  });
}

export function respondAndClose(res: ServerResponse, status: number, body: string = ''): void {
  const payload = Buffer.from(body, 'utf8');
  res.writeHead(status, { Connection: 'close', 'Content-Type': 'application/json', 'Content-Length': payload.length });
  res.end(payload, () => {
    res.req?.destroy();
  });
}

const sha256hex = (v: Buffer | string): string => createHash('sha256').update(v).digest('hex');

// Spec 2.1. LF-joined, no trailing newline.
export function canonicalV3(p: {
  t: string | number; n: string; aud: string; method: string; path: string;
  bodySha256: string; sh: string; headerHashes: Record<string, string>;
}): string {
  const names = p.sh === '' ? [] : p.sh.split(';');
  const lines = [
    'ITSL-S2S-v3',
    `t=${p.t}`,
    `n=${p.n}`,
    `aud=${p.aud}`,
    `m=${p.method}`,
    `p=${p.path}`,
    `b=${p.bodySha256}`,
    `sh=${p.sh}`,
  ];
  for (const name of names) lines.push(`${name}:${p.headerHashes[name]}`);
  return lines.join('\n');
}

const HEADER_RE = /^t=(\d{1,15}),n=([0-9a-f]{32}),sh=([a-z0-9;-]*),v3=([0-9a-f]{64})$/;

export function parseV3Header(headerValue: string): { t: number; tRaw: string; n: string; sh: string; names: string[]; v3: string } | null {
  const m = HEADER_RE.exec(headerValue);
  if (!m) return null;
  const sh = m[3];
  return { t: Number(m[1]), tRaw: m[1], n: m[2], sh, names: sh === '' ? [] : sh.split(';'), v3: m[4] };
}

// True when the value is an attempt at v3, so a malformed one is judged as v3
// and never handed to a legacy verifier.
export function looksLikeV3(headerValue: string): boolean {
  return headerValue.includes('v3=');
}

function countHeaders(rawHeaders: string[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (let i = 0; i < rawHeaders.length; i += 2) {
    const name = rawHeaders[i].toLowerCase();
    counts.set(name, (counts.get(name) ?? 0) + 1);
  }
  return counts;
}

function headerValueOf(rawHeaders: string[], lowerName: string): string {
  for (let i = 0; i < rawHeaders.length; i += 2) {
    if (rawHeaders[i].toLowerCase() === lowerName) return rawHeaders[i + 1];
  }
  return '';
}

export type HeaderRuleMode = 'enforce' | 'report';

export type VerifyArgs = {
  method: string;
  rawTarget: string;
  body: Buffer;
  rawHeaders: string[];
  secret: string;
  aud: string;
  nowSeconds?: number;
  nonceCache: NonceCache;
  // 'enforce' (default): the blanket header rule fails the request.
  // 'report': it does not; the result carries unsignedHeaderNames instead, so a
  // backend can learn which headers its platform adds before enforcing.
  headerRuleMode?: HeaderRuleMode;
  // Lower-case exact header names a backend trusts as identity (tier, user, token...).
  // A listed header that is present on the request but not covered by the signature
  // fails with 'unsigned-required-header', in report AND enforce mode. A listed header
  // that is absent is fine here (use the backend's own handling for absence). Validate
  // the list once at configuration time with assertRequireSignedHeaders().
  requireSignedHeaders?: string[];
};

// Throws on an invalid requireSignedHeaders list: anything that is not a plain
// lower-case name, the signature header itself, or an exempt (unsigned) name. Call
// once at configuration/boot time, never per request.
export function assertRequireSignedHeaders(names: string[] | undefined): void {
  for (const name of names ?? []) {
    if (typeof name !== 'string' || !/^[a-z0-9-]+$/.test(name) || name === S2S_HEADER || INGRESS_EXEMPT_HEADERS.includes(name)) {
      throw new Error(`requireSignedHeaders: invalid or exempt header name: ${String(name)}`);
    }
  }
}

// ok:true carries unsignedHeaderNames ONLY in report mode (possibly empty).
export type VerifyV3Result = { ok: true; version: 3; unsignedHeaderNames?: string[] } | VerifyFailure;

const MIN_SECRET_LENGTH = 32;

// Order matters: configuration and cheap structural checks, then the HMAC, and
// only THEN skew, the header rule and the nonce, so an unauthenticated caller
// can neither fill the nonce cache nor learn anything from those later checks,
// and a request refused by the header rule never consumes a nonce slot.
// The X-Gateway-S2S value is read from rawHeaders (after the exactly-one check),
// never passed in, so what is verified is what is counted.
export function verifyV3(a: VerifyArgs): VerifyV3Result {
  const fail = (reason: string): VerifyFailure => ({ ok: false, reason });
  const now = a.nowSeconds ?? nowSecondsDefault();

  // configuration first: a short secret or no audience is a deployment fault.
  if (typeof a.secret !== 'string' || a.secret.length < MIN_SECRET_LENGTH || typeof a.aud !== 'string' || a.aud === '') return fail('config');

  // exactly one X-Gateway-S2S in the raw headers.
  const counts = countHeaders(a.rawHeaders);
  if (counts.get(S2S_HEADER) !== 1) return fail('header-count');
  const headerValue = headerValueOf(a.rawHeaders, S2S_HEADER);

  // strict parse.
  const parsed = parseV3Header(headerValue);
  if (!parsed) return fail('header-format');

  // sh: sorted, no duplicates, no empty names, never the signature itself and
  // never an exempt name (the signer never emits those; ingress may rewrite them).
  for (let i = 0; i < parsed.names.length; i++) {
    const name = parsed.names[i];
    if (name === '' || name === S2S_HEADER || INGRESS_EXEMPT_HEADERS.includes(name)) return fail('sh-invalid');
    if (i > 0 && !(parsed.names[i - 1] < name)) return fail('sh-invalid');
  }

  // the raw request target is exactly /mcp (no query, no trailing slash).
  if (a.rawTarget !== S2S_REQUIRED_TARGET) return fail('target');

  // every listed header present exactly once, so its value can be hashed.
  const headerHashes: Record<string, string> = {};
  for (const name of parsed.names) {
    const c = counts.get(name) ?? 0;
    if (c === 0) return fail('listed-header-missing');
    if (c > 1) return fail('listed-header-duplicate');
    headerHashes[name] = sha256hex(Buffer.from(headerValueOf(a.rawHeaders, name), 'utf8'));
  }

  // HMAC, constant-time, length checked first. m is the method AS RECEIVED.
  const canonical = canonicalV3({
    t: parsed.tRaw, n: parsed.n, aud: a.aud, method: a.method, path: a.rawTarget,
    bodySha256: sha256hex(a.body), sh: parsed.sh, headerHashes,
  });
  const expected = Buffer.from(createHmac('sha256', a.secret).update(canonical, 'utf8').digest('hex'), 'utf8');
  const given = Buffer.from(parsed.v3, 'utf8');
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) return fail('hmac');

  // skew.
  if (Math.abs(now - parsed.t) > S2S_SKEW_SECONDS) return fail('skew');

  // required identity headers: present means signed (report and enforce mode alike).
  // Before the blanket rule and the nonce, so a refusal here never consumes a slot.
  if (a.requireSignedHeaders && a.requireSignedHeaders.length > 0) {
    const signedSet = new Set(parsed.names);
    for (const name of a.requireSignedHeaders) {
      if (typeof name !== 'string' || !/^[a-z0-9-]+$/.test(name) || name === S2S_HEADER || INGRESS_EXEMPT_HEADERS.includes(name)) return fail('config');
      if (counts.has(name) && !signedSet.has(name)) return fail('unsigned-required-header');
    }
  }

  // the blanket header rule: nothing sensitive that is neither signed nor
  // exempt. Exact names only; there are no prefix wildcards for exemptions.
  const signed = new Set(parsed.names);
  const unsigned: string[] = [];
  for (const name of counts.keys()) {
    if (name === S2S_HEADER || signed.has(name) || INGRESS_EXEMPT_HEADERS.includes(name)) continue;
    if (name.startsWith('x-') || name === 'authorization' || name === 'cookie' || name === 'proxy-authorization') unsigned.push(name);
  }
  unsigned.sort();
  const report = a.headerRuleMode === 'report';
  if (unsigned.length > 0 && !report) return fail('unsigned-header');

  // replay, cache-full, and only then record the nonce.
  if (a.nonceCache.has(parsed.n, now)) return fail('replay');
  if (a.nonceCache.isFull(now)) return fail('nonce-cache-full');
  a.nonceCache.add(parsed.n, parsed.t, now);

  return report ? { ok: true, version: 3, unsignedHeaderNames: unsigned } : { ok: true, version: 3 };
}

export type CheckResult =
  | { ok: true; version: number; reason?: undefined; unsignedHeaderNames?: string[] }
  | { ok: false; version: 0; reason: string };

// The single entry point a backend calls.
//  floor       the backend's own minimum, fixed in code (1; cipp 2). Required.
//  minVersion  the operator switch ITSL_S2S_MIN_VERSION. Anything that is not an
//              integer 1..3 (NaN, 0, 4, 1.5) is treated as 3, so a typo can only
//              tighten, never loosen.
// The effective minimum is max(floor, minVersion). 1 accepts v1/v2/v3, 2 accepts
// v2/v3, 3 accepts v3 only. verifyLegacy returns the legacy version the header
// verified as (1 or 2) or 0. Legacy headers get no header rule (they were never
// bound to headers) and carry no unsignedHeaderNames.
// The effective minimum version: max(floor, minVersion), where an invalid
// floor or minVersion (not an integer 1..3) counts as 3. Used by
// checkGatewayRequest and handleGatewayRequest so the two cannot drift.
export function effectiveMinVersion(floor: number, minVersion: number): number {
  const validMin = Number.isInteger(minVersion) && minVersion >= 1 && minVersion <= 3 ? minVersion : 3;
  const validFloor = Number.isInteger(floor) && floor >= 1 && floor <= 3 ? floor : 3;
  return Math.max(validFloor, validMin);
}

export function checkGatewayRequest(a: VerifyArgs & {
  floor: 1 | 2 | 3;
  minVersion: number;
  verifyLegacy?: (headerValue: string) => number;
}): CheckResult {
  const effective = effectiveMinVersion(a.floor, a.minVersion);
  const counts = countHeaders(a.rawHeaders);
  if (counts.get(S2S_HEADER) !== 1) return { ok: false, version: 0, reason: 'header-count' };
  const headerValue = headerValueOf(a.rawHeaders, S2S_HEADER);
  if (looksLikeV3(headerValue)) {
    // At the final phase (effective minimum 3) the header rule is ALWAYS enforced,
    // whatever mode the caller passed, so a backend left in report mode cannot
    // look finished while enforcing nothing on headers (security review, PR 53).
    const r = verifyV3(effective === 3 ? { ...a, headerRuleMode: 'enforce' } : a);
    if (!r.ok) return { ok: false, version: 0, reason: r.reason };
    return r.unsignedHeaderNames === undefined ? { ok: true, version: 3 } : { ok: true, version: 3, unsignedHeaderNames: r.unsignedHeaderNames };
  }
  if (effective < 3 && a.verifyLegacy) {
    const v = a.verifyLegacy(headerValue);
    if (v >= 1 && v >= effective) return { ok: true, version: v };
    return { ok: false, version: 0, reason: v >= 1 ? 'below-min-version' : 'legacy-invalid' };
  }
  return { ok: false, version: 0, reason: 'below-min-version' };
}

// Call IMMEDIATELY after a successful v3 verification, before the application
// sees the request. Removes every exempt (unsigned, ingress-rewritable) header
// from BOTH req.headers and req.rawHeaders, so nothing downstream can read a
// value that was never covered by the signature. rawHeaders is rebuilt in place.
export function stripExemptHeaders(req: { headers: Record<string, unknown>; rawHeaders: string[] }): void {
  for (const name of Object.keys(req.headers)) {
    if (INGRESS_EXEMPT_HEADERS.includes(name.toLowerCase())) delete req.headers[name];
  }
  const kept: string[] = [];
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    if (!INGRESS_EXEMPT_HEADERS.includes(req.rawHeaders[i].toLowerCase())) kept.push(req.rawHeaders[i], req.rawHeaders[i + 1]);
  }
  req.rawHeaders.splice(0, req.rawHeaders.length, ...kept);
}

// Report mode: turns the unsigned header NAMES into something safe to log.
// Lower-cased, at most 20 names, each at most 64 chars of [a-z0-9-], otherwise
// the literal "invalid-name". Header VALUES are never passed in and never logged.
export function formatUnsignedHeaderReport(names: string[]): string[] {
  const out: string[] = [];
  for (const raw of names) {
    const name = String(raw).toLowerCase();
    out.push(name.length <= 64 && /^[a-z0-9-]+$/.test(name) ? name : 'invalid-name');
  }
  return out.sort().slice(0, 20);
}

// One emit per distinct sorted name-set per window (60 s), bounded memory
// (default 1000 keys; the oldest key is evicted first), so an attacker sending
// varied headers cannot flood the log or grow memory.
export class ReportRateLimiter {
  maxKeys: number;
  windowSeconds: number;
  last: Map<string, number>;
  constructor(maxKeys: number = 1000, windowSeconds: number = 60) {
    this.maxKeys = maxKeys;
    this.windowSeconds = windowSeconds;
    this.last = new Map();
  }
  shouldEmit(names: string[] | string, now: number = nowSecondsDefault()): boolean {
    const key = typeof names === 'string' ? names : [...names].sort().join(';');
    const prev = this.last.get(key);
    if (prev !== undefined && now - prev < this.windowSeconds) return false;
    this.last.delete(key);
    this.last.set(key, now);
    while (this.last.size > this.maxKeys) {
      const oldest = this.last.keys().next().value as string;
      this.last.delete(oldest);
    }
    return true;
  }
}

// ---------------------------------------------------------------------------
// The shared request wrapper. Every backend's /mcp handler goes through this, so
// the guard is identical everywhere. The returned promise NEVER rejects: an
// aborted upload, a throwing handler or a bad body ends THAT request, not the
// process (there is no unhandledRejection handler in the backends).
// ---------------------------------------------------------------------------

export type GatewayLogger = {
  warn(msg: string, meta?: Record<string, unknown>): void;
  error(msg: string, meta?: Record<string, unknown>): void;
  debug?(msg: string, meta?: Record<string, unknown>): void;
};

export type GatewayOptions = {
  secret: string | undefined; // empty/undefined => S2S disabled (only via each backend's dev escape hatch)
  aud: string;
  floor: 1 | 2 | 3;
  minVersion: number; // raw, unvalidated (the verifier treats invalid as 3)
  verifyLegacy?: (headerValue: string) => number;
  nonceCache: NonceCache;
  reportLimiter: ReportRateLimiter;
  failureLimiter: ReportRateLimiter; // keyed by reason
  logger: GatewayLogger;
  bodyLimitBytes?: number; // default 5 MB
  // Only a backend's explicit dev escape hatch may set this. Without it a missing
  // secret is a deployment fault: the request is refused, never served unauthenticated.
  allowUnauthenticated?: boolean;
  // Passed to the verifier: see VerifyArgs.requireSignedHeaders. Validate with
  // assertRequireSignedHeaders() at boot.
  requireSignedHeaders?: string[];
};

export type VerifiedRequest = { version: number; parsedBody: unknown; headerRuleEnforced: boolean };

const GENERIC_401 = '{"error":"Missing or invalid X-Gateway-S2S header"}';
const BODY_METHODS = ['POST', 'PUT', 'PATCH'];

export async function handleGatewayRequest(
  req: IncomingMessage,
  res: ServerResponse,
  opts: GatewayOptions,
  onVerified: (v: VerifiedRequest) => Promise<void> | void,
): Promise<void> {
  try {
    const secret = opts.secret;
    const logFailure = (reason: string): void => {
      if (opts.failureLimiter.shouldEmit(reason)) opts.logger.warn('S2S verification failed', { reason });
    };

    // 0. No secret is a configuration fault unless the dev escape hatch said otherwise.
    if (!secret && opts.allowUnauthenticated !== true) {
      logFailure('config');
      respondAndClose(res, 500, '{"error":"internal_error"}');
      return;
    }

    // 1. Nothing is buffered for a request that cannot verify.
    if (secret && countHeaders(req.rawHeaders).get(S2S_HEADER) !== 1) {
      logFailure('header-count');
      respondAndClose(res, 401, GENERIC_401);
      return;
    }

    // 2. Read the exact bytes. A socket abort is not our error to answer.
    let body: Buffer;
    try {
      body = await readRawBody(req, opts.bodyLimitBytes);
    } catch (err) {
      if (err instanceof RawBodyError) {
        respondAndClose(res, err.status, JSON.stringify({ error: 'Request body rejected' }));
      } else {
        req.destroy();
        res.destroy();
      }
      return;
    }

    // 3. Verify.
    let version = 0;
    let headerRuleEnforced = false;
    if (secret) {
      const check = checkGatewayRequest({
        method: req.method ?? '',
        rawTarget: req.url ?? '',
        body,
        rawHeaders: req.rawHeaders,
        secret,
        aud: opts.aud,
        nonceCache: opts.nonceCache,
        floor: opts.floor,
        minVersion: opts.minVersion,
        verifyLegacy: opts.verifyLegacy,
        headerRuleMode: 'report',
        requireSignedHeaders: opts.requireSignedHeaders,
      });
      if (!check.ok) {
        logFailure(check.reason);
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(GENERIC_401);
        return;
      }
      version = check.version;
      if (version === 3) {
        stripExemptHeaders(req);
        const unsigned = check.unsignedHeaderNames;
        if (unsigned && unsigned.length > 0) {
          const names = formatUnsignedHeaderReport(unsigned);
          if (opts.reportLimiter.shouldEmit(names)) opts.logger.warn('S2S v3 request carried unsigned headers', { unsignedHeaders: names });
        }
        headerRuleEnforced = effectiveMinVersion(opts.floor, opts.minVersion) === 3;
      }
      opts.logger.debug?.('S2S verified', { version });
    }

    // 4. Body.
    let parsedBody: unknown;
    if (body.length === 0) {
      if (BODY_METHODS.includes((req.method ?? '').toUpperCase())) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end('{"error":"Empty body"}');
        return;
      }
    } else {
      try {
        parsedBody = JSON.parse(body.toString('utf8'));
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end('{"error":"Invalid JSON body"}');
        return;
      }
    }

    // 5. The backend's own handling.
    await onVerified({ version, parsedBody, headerRuleEnforced });
  } catch (err) {
    // 6. Never rethrow. Message only: no headers, no body.
    try { opts.logger.error('gateway request failed', { error: String((err as Error)?.message ?? err) }); } catch { /* logging must not throw */ }
    try {
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json', Connection: 'close' });
        res.end('{"error":"internal_error"}');
      } else {
        res.destroy();
      }
    } catch { /* already gone */ }
  }
}
