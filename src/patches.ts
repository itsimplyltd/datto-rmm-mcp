/**
 * Windows patch installation/compliance data for a device or site.
 *
 * Datto RMM 15.1.0 (rolled out July-Aug 2026) added two new v2 endpoints -
 * GET /v2/device/{deviceUid}/patches and GET /v2/site/{siteUid}/patches -
 * that the upstream @wyre-technology/node-datto-rmm SDK doesn't wrap yet
 * (checked main as of this writing: no resources/patches.ts). DattoRmmClient
 * keeps its HttpClient/AuthManager private, so there's no way to piggyback
 * on the SDK's own token caching from outside it without either forking the
 * SDK too or reaching into its internals - this instead goes through
 * `dattoGet` (src/rmm-api.ts), which does its own minimal OAuth token
 * acquisition, deliberately mirroring node-datto-rmm's src/auth.ts and
 * src/config.ts exactly (same token endpoint, same public-client:public
 * Basic auth, same platform->URL map), so swapping this out for a real SDK
 * method later (once/if upstream adds one) is a drop-in replacement rather
 * than a behavior change.
 *
 * Live-tested against our own Datto RMM account (syrah platform) before
 * writing this: GET /v2/device/{uid}/patches returns
 * { pageDetails, patches: [{ patchId, category, type, title, description,
 * releaseDate, severity, maxSize, rebootRequired, requireUserInput,
 * kbArticleId, installStatus, manualOverride }] } - installStatus is the
 * per-patch installed/missing/pending signal this module exists to expose.
 *
 * GET /v2/site/{siteUid}/patches is SINGULAR "site", not "sites" - this
 * module called the plural form until 4 Oct 2026, which 404s live with
 * "No static resource v2/sites/...". Fixed to match the real path.
 */

import type { DattoCredentials } from "./mcp-server.js";
import { dattoGet } from "./rmm-api.js";

export interface Patch {
  patchId: string;
  category: string[];
  type: string;
  title: string;
  description: string;
  releaseDate: string;
  severity: string;
  maxSize: number;
  rebootRequired: boolean;
  requireUserInput: boolean;
  kbArticleId: string;
  installStatus: string;
  manualOverride: boolean;
}

export interface PatchesResponse {
  pageDetails: {
    count: number;
    totalCount: number;
    prevPageUrl: string | null;
    nextPageUrl: string | null;
  };
  patches: Patch[];
}

export type InstallStatus = "INSTALLED" | "APPROVED_PENDING" | "NOT_APPROVED";

export interface PatchListOptions {
  installStatus?: InstallStatus;
  includeDescriptions?: boolean;
  max?: number;
}

/**
 * What the patch tools return. `totalCount` is Datto's own count, so a caller
 * can always tell a complete answer from a capped one. The API pages these
 * endpoints at 250 rows, and returning the first page as if it were the whole
 * list (as this server did until 1.9.0-itsl3) reads as a complete answer.
 */
export interface PatchList {
  totalCount: number;
  returned: number;
  truncated: boolean;
  patches: Array<Record<string, unknown>>;
}

/** Datto refuses page sizes above 250 ("exceeds the defined limit of 250"). */
const PATCH_PAGE_SIZE = 250;
const DEFAULT_PATCH_MAX = 2000;

async function listPatches(
  creds: DattoCredentials,
  path: string,
  opts: PatchListOptions
): Promise<PatchList> {
  const max = Math.max(1, Math.min(opts.max ?? DEFAULT_PATCH_MAX, 10000));
  const patches: PatchList["patches"] = [];
  let totalCount = 0;
  // Datto pages these by number (page=0,1,...), not by cursor. Stop on a null
  // nextPageUrl, an empty page, or the cap. Never fetch nextPageUrl itself.
  for (let page = 0; page < 1000 && patches.length < max; page++) {
    const res = await dattoGet<PatchesResponse>(creds, path, {
      page,
      max: PATCH_PAGE_SIZE,
      installStatus: opts.installStatus,
    });
    totalCount = res.pageDetails?.totalCount ?? totalCount;
    const rows = res.patches ?? [];
    for (const row of rows) {
      if (patches.length >= max) break;
      if (opts.includeDescriptions) {
        patches.push({ ...row });
      } else {
        const { description: _omit, ...rest } = row;
        patches.push(rest);
      }
    }
    if (!res.pageDetails?.nextPageUrl || rows.length === 0) break;
  }
  if (totalCount < patches.length) totalCount = patches.length;
  return { totalCount, returned: patches.length, truncated: patches.length < totalCount, patches };
}

export function getDevicePatches(
  creds: DattoCredentials,
  deviceUid: string,
  opts: PatchListOptions = {}
): Promise<PatchList> {
  return listPatches(creds, `/v2/device/${encodeURIComponent(deviceUid)}/patches`, {
    includeDescriptions: true,
    ...opts,
  });
}

export function getSitePatches(
  creds: DattoCredentials,
  siteUid: string,
  opts: PatchListOptions = {}
): Promise<PatchList> {
  return listPatches(creds, `/v2/site/${encodeURIComponent(siteUid)}/patches`, opts);
}
