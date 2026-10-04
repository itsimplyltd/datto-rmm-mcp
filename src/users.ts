/**
 * RMM console user accounts: `GET /v2/account/users`.
 *
 * Confirmed live against our own Datto RMM account (syrah platform,
 * 4 Oct 2026): 35 users, all on one page. Paginates internally (there's no
 * caller-facing cursor here, unlike activity logs) via the safe
 * query-string-only follow in `dattoGetAllPages`, capped at 1000 users.
 *
 * There is no user id in this payload, so it cannot be joined to activity
 * log `userIds` filters - activity log rows already carry the user's name
 * directly instead.
 */

import type { DattoCredentials } from "./mcp-server.js";
import { dattoGetAllPages } from "./rmm-api.js";

interface RawAuthUser {
  lastName?: string;
  firstName?: string;
  username?: string;
  email?: string;
  telephone?: string;
  status?: string;
  created?: string | number;
  lastAccess?: string | number;
  disabled?: boolean;
}

interface RawUsersPage {
  pageDetails: {
    count: number;
    totalCount?: number;
    prevPageUrl: string | null;
    nextPageUrl: string | null;
  };
  users: RawAuthUser[];
}

/** `telephone` is dropped (data minimisation) - every other field is kept. */
export interface RmmUser {
  lastName?: string;
  firstName?: string;
  username?: string;
  email?: string;
  status?: string;
  created?: string;
  lastAccess?: string;
  disabled?: boolean;
}

export interface ListUsersResult {
  count: number;
  users: RmmUser[];
}

const MAX_USERS = 1000;

/**
 * The spec types `created`/`lastAccess` as ISO date-time strings, but this
 * codebase has already found other Datto v2 endpoints sending epoch numbers
 * for similarly-named fields (see activity-logs.ts's `date`), so this
 * checks the runtime type rather than trusting the spec. A number under the
 * year-2001-in-milliseconds threshold is treated as epoch seconds, matching
 * the activity log convention; a larger number is treated as epoch
 * milliseconds.
 */
function toIso(value: string | number | undefined): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value === "string") return value;
  const ms = value < 1e12 ? value * 1000 : value;
  const date = new Date(ms);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

export async function listUsers(creds: DattoCredentials): Promise<ListUsersResult> {
  const users = await dattoGetAllPages<RawUsersPage, RawAuthUser>(
    creds,
    "/v2/account/users",
    {},
    (page) => page.users,
    (page) => page.pageDetails?.nextPageUrl,
    MAX_USERS
  );

  return {
    count: users.length,
    users: users.map((u) => ({
      lastName: u.lastName,
      firstName: u.firstName,
      username: u.username,
      email: u.email,
      status: u.status,
      created: toIso(u.created),
      lastAccess: toIso(u.lastAccess),
      disabled: u.disabled,
    })),
  };
}
