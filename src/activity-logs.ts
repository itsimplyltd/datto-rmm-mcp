/**
 * The RMM activity log: `GET /v2/activity-logs`.
 *
 * Confirmed live against our own Datto RMM account (syrah platform, 4 Oct
 * 2026). Covers who remotely took over or screen-controlled a device and
 * when, web remote PowerShell sessions, file transfers, jobs created and
 * deployed, console logins, and patch runs.
 *
 * Paging uses Datto's `searchAfter` cursor, carried in the response's
 * `pageDetails.nextPageUrl`. We never fetch that URL directly (see
 * `dattoGet`'s header comment on why) - instead we pull the `searchAfter`
 * value(s) out of its query string and hand them back to our own caller as
 * an opaque, base64url-encoded cursor. The caller passes that cursor back
 * on the next call, and we decode it, resend `searchAfter` plus
 * `page=next`, and merge in whatever filters they pass this time.
 */

import type { DattoCredentials } from "./mcp-server.js";
import {
  dattoGet,
  decodeCursor,
  encodeCursor,
  extractSearchAfter,
  type DattoQuery,
} from "./rmm-api.js";

interface RawActivityLog {
  id: string;
  entity: string;
  category: string;
  action: string;
  /** Epoch seconds (may carry a fractional nanosecond part per the spec). */
  date: number;
  site?: { id: number; name: string };
  deviceId?: number;
  hostname?: string;
  user?: { id: number; userName: string; firstName: string; lastName: string };
  /** A JSON string of flattened dotted keys, e.g. `"user.id"`. */
  details?: string;
  hasStdOut?: boolean;
  hasStdErr?: boolean;
}

interface RawActivityLogsPage {
  pageDetails: {
    count: number;
    prevPageUrl: string | null;
    nextPageUrl: string | null;
  };
  activities: RawActivityLog[];
}

export interface ActivityLogEntry
  extends Omit<RawActivityLog, "date" | "details"> {
  /** ISO 8601 string, converted from the API's epoch-seconds `date`. */
  date: string;
  /** Parsed from the API's JSON-string `details`; kept raw if parsing fails. */
  details: unknown;
}

export interface ActivityLogsResult {
  count: number;
  nextCursor: string | null;
  activities: ActivityLogEntry[];
}

export interface ListActivityLogsInput {
  from?: string;
  until?: string;
  entities?: string[];
  categories?: string[];
  actions?: string[];
  siteIds?: number[];
  userIds?: number[];
  searchQuery?: string;
  order?: "asc" | "desc";
  size?: number;
  cursor?: string;
}

const DEFAULT_LOOKBACK_MS = 24 * 60 * 60 * 1000;
const MAX_SIZE = 250;
const DEFAULT_SIZE = 100;

/**
 * Normalises any `Date`-parseable input to the exact UTC format the API
 * requires: `yyyy-MM-ddTHH:mm:ssZ`, with no milliseconds.
 */
export function normalizeDateTime(input: string | Date): string {
  const parsed = input instanceof Date ? input : new Date(input);
  if (Number.isNaN(parsed.getTime())) {
    throw new Error(`Invalid date: "${String(input)}"`);
  }
  return parsed.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function clampSize(size: number | undefined): number {
  const n = size ?? DEFAULT_SIZE;
  return Math.min(MAX_SIZE, Math.max(1, Math.trunc(n)));
}

function parseDetails(raw: string | undefined): unknown {
  if (raw === undefined) return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

export async function listActivityLogs(
  creds: DattoCredentials,
  input: ListActivityLogsInput
): Promise<ActivityLogsResult> {
  const query: DattoQuery = {
    from: normalizeDateTime(input.from ?? new Date(Date.now() - DEFAULT_LOOKBACK_MS)),
    until: input.until ? normalizeDateTime(input.until) : undefined,
    entities: input.entities,
    categories: input.categories,
    actions: input.actions,
    siteIds: input.siteIds,
    userIds: input.userIds,
    searchQuery: input.searchQuery,
    order: input.order ?? "desc",
    size: clampSize(input.size),
  };

  if (input.cursor) {
    query.searchAfter = decodeCursor(input.cursor);
    query.page = "next";
  }

  const page = await dattoGet<RawActivityLogsPage>(creds, "/v2/activity-logs", query);

  const nextCursor = page.pageDetails.nextPageUrl
    ? encodeCursor(extractSearchAfter(page.pageDetails.nextPageUrl))
    : null;

  const activities: ActivityLogEntry[] = (page.activities ?? []).map((activity) => ({
    ...activity,
    date: new Date(activity.date * 1000).toISOString(),
    details: parseDetails(activity.details),
  }));

  return {
    count: page.pageDetails.count,
    nextCursor,
    activities,
  };
}
