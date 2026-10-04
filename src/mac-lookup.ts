/**
 * Device lookup by MAC address: `GET /v2/device/macAddress/{macAddress}`.
 *
 * The spec's summary for this path reads: "Fetches data of the device(s)
 * identified by the given MAC address in format: XXXXXXXXXXXX" - i.e. 12
 * hex characters, no separators. This module accepts the common
 * human-entered formats (colon-, dash-, or dot-separated, or bare hex) and
 * normalises to that exact format before calling the API.
 */

import type { Device } from "@wyre-ai/node-datto-rmm";
import type { DattoCredentials } from "./mcp-server.js";
import { dattoGet } from "./rmm-api.js";

/**
 * Strips `:`, `-`, and `.` separators and requires exactly 12 hex
 * characters, uppercased - the format the live API's spec documents.
 * Throws a clear validation error on anything else rather than letting a
 * malformed address reach the API as a confusing 404/400.
 */
export function normalizeMacAddress(input: string): string {
  const stripped = input.replace(/[:\-.]/g, "");
  if (!/^[0-9a-fA-F]{12}$/.test(stripped)) {
    throw new Error(
      `Invalid MAC address "${input}": expected 12 hex characters, optionally separated by ':', '-', or '.' (e.g. aa:bb:cc:dd:ee:ff)`
    );
  }
  return stripped.toUpperCase();
}

export function findDevicesByMacAddress(
  creds: DattoCredentials,
  macAddress: string
): Promise<Device[]> {
  const normalized = normalizeMacAddress(macAddress);
  return dattoGet<Device[]>(creds, `/v2/device/macAddress/${normalized}`);
}
