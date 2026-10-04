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

export function getDevicePatches(creds: DattoCredentials, deviceUid: string): Promise<PatchesResponse> {
  return dattoGet<PatchesResponse>(creds, `/v2/device/${encodeURIComponent(deviceUid)}/patches`);
}

export function getSitePatches(creds: DattoCredentials, siteUid: string): Promise<PatchesResponse> {
  return dattoGet<PatchesResponse>(creds, `/v2/site/${encodeURIComponent(siteUid)}/patches`);
}
