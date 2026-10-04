/**
 * Shared low-level HTTP client for Datto RMM v2 API endpoints that the
 * `@wyre-ai/node-datto-rmm` SDK doesn't wrap (yet). Originally lived inline
 * in `patches.ts` (see that file's header comment for why this does its own
 * OAuth token acquisition rather than piggybacking on the SDK's private
 * `HttpClient`/`AuthManager`); generalised here once a second and third
 * batch of unwrapped endpoints needed the exact same fetch-with-retry
 * behaviour, so every direct-fetch tool goes through one `dattoGet` helper
 * instead of re-implementing the token cache and retry-on-401 logic.
 */

import type { Platform } from "@wyre-ai/node-datto-rmm";
import type { DattoCredentials } from "./mcp-server.js";

export const PLATFORM_URLS: Record<Platform, string> = {
  pinotage: "https://pinotage-api.centrastage.net",
  merlot: "https://merlot-api.centrastage.net",
  concord: "https://concord-api.centrastage.net",
  vidal: "https://vidal-api.centrastage.net",
  zinfandel: "https://zinfandel-api.centrastage.net",
  syrah: "https://syrah-api.centrastage.net",
};

// One token per CREDENTIAL SET (platform + apiKey), refreshed on expiry -
// deliberately not shared with DattoRmmClient's own AuthManager (that
// instance is per-request in gateway mode anyway, per mcp-server.ts's header
// comment on credential isolation), so this trades a little redundant token
// acquisition for staying fully decoupled from the SDK's private internals.
//
// Keyed by platform+apiKey rather than a single module-level slot: this
// server runs in gateway mode, i.e. one process handling many different MSP
// customers' credentials over its lifetime. With only six platform values
// and presumably many more than six customers, a platform-only key meant any
// two customers on the same platform bucket would collide and silently
// receive each other's cached access token - a cross-tenant credential leak,
// not a hypothetical. apiKey uniquely identifies the credential set without
// needing to hash in apiSecretKey too.
const tokenCache = new Map<string, { accessToken: string; expiresAt: number }>();

function tokenCacheKey(creds: DattoCredentials): string {
  return `${creds.platform}:${creds.apiKey}`;
}

async function getAccessToken(creds: DattoCredentials): Promise<string> {
  const apiUrl = PLATFORM_URLS[creds.platform];
  const cacheKey = tokenCacheKey(creds);

  const cached = tokenCache.get(cacheKey);
  if (cached && Date.now() < cached.expiresAt - 5 * 60 * 1000) {
    return cached.accessToken;
  }

  const basicAuth = Buffer.from("public-client:public").toString("base64");
  const response = await fetch(`${apiUrl}/auth/oauth/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
    },
    body: new URLSearchParams({
      grant_type: "password",
      username: creds.apiKey,
      password: creds.apiSecretKey,
    }).toString(),
  });

  if (!response.ok) {
    // Drain the body (Datto's own OAuth error detail) without relaying it -
    // this can propagate straight through to an MCP tool-call result, and an
    // auth-failure response body gets the same caution as any other one
    // would before being surfaced to a caller.
    await response.text();
    throw new Error(`Failed to acquire Datto RMM token: ${response.status} ${response.statusText}`);
  }

  const data = (await response.json()) as { access_token: string; expires_in: number };
  tokenCache.set(cacheKey, { accessToken: data.access_token, expiresAt: Date.now() + data.expires_in * 1000 });
  return data.access_token;
}

/**
 * Query parameter values `dattoGet` accepts. An array is sent comma-joined
 * (the Datto RMM API's convention for multi-value filters, e.g.
 * `categories=remote,web.remote`) - never as repeated keys. `undefined`
 * values are omitted entirely rather than sent as the literal string
 * "undefined".
 */
export type DattoQuery = Record<
  string,
  string | number | boolean | Array<string | number> | undefined
>;

function buildQueryString(query?: DattoQuery): string {
  if (!query) return "";
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) {
      if (value.length === 0) continue;
      params.set(key, value.join(","));
    } else {
      params.set(key, String(value));
    }
  }
  const qs = params.toString();
  return qs ? `?${qs}` : "";
}

/**
 * GET against a Datto RMM v2 API path, with the same per-credential token
 * caching and one-retry-on-401 behaviour as the rest of this server.
 *
 * Only ever fetches `${PLATFORM_URLS[creds.platform]}/api${path}` - callers
 * must pass a path (and, if relevant, a cursor extracted from a prior
 * response's query string), never a full URL taken from an API response.
 * Following a server-returned URL directly would let Datto (or anyone able
 * to influence that response) redirect this server's authenticated requests
 * to an arbitrary host - the SSRF risk callers must avoid.
 */
export async function dattoGet<T>(
  creds: DattoCredentials,
  path: string,
  query?: DattoQuery
): Promise<T> {
  const apiUrl = PLATFORM_URLS[creds.platform];
  const qs = buildQueryString(query);
  const url = `${apiUrl}/api${path}${qs}`;
  const token = await getAccessToken(creds);

  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (response.status === 401) {
    // Token may have been invalidated server-side - retry once with a fresh
    // one. Only this credential set's entry, not the whole cache - other
    // customers' still-valid cached tokens shouldn't be forced to
    // re-authenticate because of one unrelated 401.
    tokenCache.delete(tokenCacheKey(creds));
    const retryToken = await getAccessToken(creds);
    const retryResponse = await fetch(url, {
      headers: { Authorization: `Bearer ${retryToken}` },
    });
    if (!retryResponse.ok) {
      const body = await retryResponse.text();
      throw new Error(`Datto RMM API error: ${retryResponse.status} ${retryResponse.statusText} - ${body}`);
    }
    return (await retryResponse.json()) as T;
  }

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Datto RMM API error: ${response.status} ${response.statusText} - ${body}`);
  }

  return (await response.json()) as T;
}

/**
 * Parses a Datto RMM paginated response's `nextPageUrl` and returns its
 * query string as a plain `DattoQuery` object - the safe way to "follow" a
 * page link. We never fetch the URL itself (that would let a response
 * redirect this server's authenticated requests to an arbitrary host); we
 * only read the query parameters Datto told us to send next (e.g. `page=2`,
 * or `searchAfter=...&page=next`) and replay them against the same `path`
 * via `dattoGet`. Repeated keys (`searchAfter` can appear more than once)
 * come back as an array.
 */
export function nextPageQuery(nextPageUrl: string): DattoQuery {
  const url = new URL(nextPageUrl);
  const query: DattoQuery = {};
  for (const key of new Set(url.searchParams.keys())) {
    const values = url.searchParams.getAll(key);
    query[key] = values.length > 1 ? values : values[0];
  }
  return query;
}

/** Extracts just the `searchAfter` value(s) from a `nextPageUrl`, for building a caller-facing cursor. */
export function extractSearchAfter(nextPageUrl: string): string[] {
  return new URL(nextPageUrl).searchParams.getAll("searchAfter");
}

/** Base64url-encodes a JSON array of `searchAfter` values into an opaque cursor string. */
export function encodeCursor(searchAfter: string[]): string {
  return Buffer.from(JSON.stringify(searchAfter), "utf8").toString("base64url");
}

/** Decodes a cursor produced by `encodeCursor` back into `searchAfter` values. Throws on malformed input. */
export function decodeCursor(cursor: string): string[] {
  let decoded: unknown;
  try {
    decoded = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8"));
  } catch {
    throw new Error(`Invalid cursor: "${cursor}"`);
  }
  if (!Array.isArray(decoded) || !decoded.every((v) => typeof v === "string")) {
    throw new Error(`Invalid cursor: "${cursor}"`);
  }
  return decoded;
}

/**
 * Repeatedly calls `dattoGet` against `path`, following `nextPageUrl` (via
 * `nextPageQuery` - never fetched directly) until either the page stops
 * supplying one or `max` items have been collected. Used for tools that
 * paginate internally and just want a flat, capped item list back (as
 * opposed to activity logs, which hands an opaque cursor back to the
 * caller instead of paginating internally).
 */
export async function dattoGetAllPages<TPage, TItem>(
  creds: DattoCredentials,
  path: string,
  initialQuery: DattoQuery,
  getItems: (page: TPage) => TItem[] | undefined,
  getNextPageUrl: (page: TPage) => string | null | undefined,
  max: number
): Promise<TItem[]> {
  const items: TItem[] = [];
  let query: DattoQuery | undefined = initialQuery;

  // Hard iteration cap as a defensive backstop against an API that somehow
  // never stops supplying a nextPageUrl - not expected, but cheap to guard.
  for (let pagesFetched = 0; pagesFetched < 1000; pagesFetched++) {
    const page = await dattoGet<TPage>(creds, path, query);
    for (const item of getItems(page) ?? []) {
      items.push(item);
      if (items.length >= max) return items;
    }
    const nextUrl = getNextPageUrl(page);
    if (!nextUrl) break;
    query = nextPageQuery(nextUrl);
  }

  return items;
}
