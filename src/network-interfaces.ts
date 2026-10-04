/**
 * IP/MAC addresses for every device in a site:
 * `GET /v2/site/{siteUid}/devices/network-interface`.
 *
 * Confirmed from the spec's schema: the array key is `devices` (each entry
 * is a "Device Network Interface" object), and each device's interfaces are
 * under `nics` (a "NetworkInterface" object: `instance`, `ipv4`, `ipv6`,
 * `macAddress`, `type`).
 *
 * Paginates internally via the safe query-string-only follow in
 * `dattoGetAllPages`, capped at the caller's `max`.
 */

import type { DattoCredentials } from "./mcp-server.js";
import { dattoGetAllPages } from "./rmm-api.js";

export interface NetworkInterface {
  instance?: string;
  ipv4?: string;
  ipv6?: string;
  macAddress?: string;
  type?: string;
}

interface RawDeviceNetworkInterface {
  uid?: string;
  siteUid?: string;
  siteName?: string;
  hostname?: string;
  intIpAddress?: string;
  extIpAddress?: string;
  nics?: NetworkInterface[];
}

interface RawNetworkInterfacePage {
  pageDetails: {
    count: number;
    totalCount?: number;
    prevPageUrl: string | null;
    nextPageUrl: string | null;
  };
  devices: RawDeviceNetworkInterface[];
}

export interface DeviceNetworkInterfaces {
  uid?: string;
  hostname?: string;
  siteUid?: string;
  siteName?: string;
  intIpAddress?: string;
  extIpAddress?: string;
  nics: NetworkInterface[];
}

export interface ListSiteNetworkInterfacesResult {
  count: number;
  devices: DeviceNetworkInterfaces[];
}

const DEFAULT_MAX = 250;
const API_PAGE_SIZE_CAP = 250;

export async function listSiteNetworkInterfaces(
  creds: DattoCredentials,
  siteUid: string,
  max: number = DEFAULT_MAX
): Promise<ListSiteNetworkInterfacesResult> {
  const cap = Math.max(1, Math.trunc(max));
  const pageSize = Math.min(API_PAGE_SIZE_CAP, cap);

  const devices = await dattoGetAllPages<RawNetworkInterfacePage, RawDeviceNetworkInterface>(
    creds,
    `/v2/site/${encodeURIComponent(siteUid)}/devices/network-interface`,
    { max: pageSize },
    (page) => page.devices,
    (page) => page.pageDetails?.nextPageUrl,
    cap
  );

  return {
    count: devices.length,
    devices: devices.map((d) => ({
      uid: d.uid,
      hostname: d.hostname,
      siteUid: d.siteUid,
      siteName: d.siteName,
      intIpAddress: d.intIpAddress,
      extIpAddress: d.extIpAddress,
      nics: d.nics ?? [],
    })),
  };
}
