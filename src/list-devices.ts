/**
 * datto_list_devices, rewritten to call Datto RMM's device endpoints directly
 * so that filters are actually applied and the caller can tell a complete
 * answer from a capped one.
 *
 * Why: the earlier version accepted only siteUid and max, but MCP clients
 * would pass other plausible filters (deviceType, deviceClass) that were
 * silently dropped. The result was the head of the unfiltered fleet cut to
 * `max`, which reads as a confident answer: "filtered for ESXi hosts, none
 * found" when one existed (found 2026-10-05).
 *
 * Live API facts (syrah, verified 2026-10-05):
 * - GET /v2/account/devices accepts hostname, deviceType, operatingSystem and
 *   siteName, each a case-insensitive LIKE (partial match). deviceType matches
 *   deviceType.category, e.g. "esxi" finds category "ESXi Host".
 * - GET /v2/site/{siteUid}/devices accepts none of those, so with siteUid the
 *   same filters are applied here, client-side, with the same partial-match
 *   semantics.
 * - deviceClass is not an API filter at all; it has two values across the
 *   fleet ("device", "esxihost") and is always filtered client-side.
 * - Page size limit is 250, pages are numbered from 0, and pageDetails
 *   carries totalCount.
 */

import type { DattoCredentials } from "./mcp-server.js";
import { dattoGet } from "./rmm-api.js";

export interface ListDevicesInput {
  siteUid?: string;
  hostname?: string;
  deviceType?: string;
  operatingSystem?: string;
  siteName?: string;
  deviceClass?: "device" | "esxihost";
  max?: number;
}

export interface ListDevicesResult {
  /** Number of devices matching every filter. Exact unless `scanCapped`. */
  totalCount: number;
  returned: number;
  /** True when more devices match than were returned. */
  truncated: boolean;
  /** True when a client-side filter stopped scanning at the safety cap, so totalCount is a lower bound. */
  scanCapped: boolean;
  devices: Array<Record<string, unknown>>;
}

interface DevicesPage {
  pageDetails?: { totalCount?: number; nextPageUrl?: string | null };
  devices?: Array<Record<string, unknown>>;
}

const PAGE_SIZE = 250;
const DEFAULT_MAX = 50;
const MAX_LIMIT = 5000;
/** Most devices a client-side filter will scan before giving up; the live fleet is about 1,230. */
const SCAN_LIMIT = 20000;

function contains(haystack: unknown, needle: string): boolean {
  return typeof haystack === "string" && haystack.toLowerCase().includes(needle.toLowerCase());
}

function matchesClientFilters(device: Record<string, unknown>, input: ListDevicesInput, withApiFilters: boolean): boolean {
  if (input.deviceClass && device.deviceClass !== input.deviceClass) return false;
  if (!withApiFilters) return true;
  if (input.hostname && !contains(device.hostname, input.hostname)) return false;
  if (input.operatingSystem && !contains(device.operatingSystem, input.operatingSystem)) return false;
  if (input.siteName && !contains(device.siteName, input.siteName)) return false;
  if (input.deviceType) {
    const dt = (device.deviceType ?? {}) as { category?: unknown; type?: unknown };
    if (!contains(dt.category, input.deviceType) && !contains(dt.type, input.deviceType)) return false;
  }
  return true;
}

export async function listDevices(
  creds: DattoCredentials,
  input: ListDevicesInput,
  shape: (device: Record<string, unknown>) => Record<string, unknown>
): Promise<ListDevicesResult> {
  const max = Math.max(1, Math.min(input.max ?? DEFAULT_MAX, MAX_LIMIT));
  const bySite = Boolean(input.siteUid);
  const path = bySite
    ? `/v2/site/${encodeURIComponent(input.siteUid as string)}/devices`
    : "/v2/account/devices";
  // Filters the API applies itself (account endpoint only).
  const apiFilters = bySite
    ? {}
    : {
        hostname: input.hostname,
        deviceType: input.deviceType,
        operatingSystem: input.operatingSystem,
        siteName: input.siteName,
      };
  // Anything the API cannot filter means every page must be scanned to know the true count.
  const clientSide = Boolean(input.deviceClass) || (bySite && Boolean(input.hostname || input.deviceType || input.operatingSystem || input.siteName));

  const devices: Array<Record<string, unknown>> = [];
  let matched = 0;
  let scanned = 0;
  let apiTotal = 0;
  let scanCapped = false;

  for (let page = 0; page < 1000; page++) {
    const res = await dattoGet<DevicesPage>(creds, path, { page, max: PAGE_SIZE, ...apiFilters });
    apiTotal = res.pageDetails?.totalCount ?? apiTotal;
    const rows = res.devices ?? [];
    for (const row of rows) {
      scanned++;
      if (!matchesClientFilters(row, input, bySite)) continue;
      matched++;
      if (devices.length < max) devices.push(shape(row));
    }
    const more = Boolean(res.pageDetails?.nextPageUrl) && rows.length > 0;
    if (!more) break;
    // Without client-side filtering, the API total is exact, so stop once we have enough.
    if (!clientSide && devices.length >= max) break;
    if (scanned >= SCAN_LIMIT) {
      scanCapped = true;
      break;
    }
  }

  const totalCount = clientSide ? matched : Math.max(apiTotal, devices.length);
  return {
    totalCount,
    returned: devices.length,
    truncated: devices.length < totalCount || scanCapped,
    scanCapped,
    devices,
  };
}
