/**
 * ESXi host audit data: `GET /v2/audit/esxihost/{deviceUid}`.
 *
 * Per the spec, this 400s with "The device identified by the given device
 * UID is not of class ESXi host" for any device that isn't actually an
 * ESXi host. IT Simply has no ESXi hosts in its managed fleet, so a live
 * call against any real device is expected to surface that error (not a
 * silent empty success) - documented in the tool description, not handled
 * specially here, since it's the same error-propagation path every other
 * direct-fetch tool uses.
 */

import type { DattoCredentials } from "./mcp-server.js";
import { dattoGet } from "./rmm-api.js";

export function getEsxiHostAudit(
  creds: DattoCredentials,
  deviceUid: string
): Promise<unknown> {
  return dattoGet<unknown>(creds, `/v2/audit/esxihost/${encodeURIComponent(deviceUid)}`);
}
