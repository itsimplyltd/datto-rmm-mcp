/**
 * Shared MCP server factory for Datto RMM.
 *
 * This module is **side-effect free** (importing it never starts a transport),
 * so it can be reused by every entrypoint:
 * - `index.ts` — stdio + Node HTTP transport
 * - `worker.ts` — Cloudflare Workers (Web Standard) transport
 *
 * All tools are exposed upfront for universal MCP client compatibility. A fresh
 * server is created per request (for credential isolation in HTTP/Workers mode).
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import {
  DattoRmmClient,
  type Component,
  type Device,
  type Platform,
  type QuickJobRequest,
} from "@wyre-ai/node-datto-rmm";
import { elicitSelection } from "./utils/elicitation.js";
import {
  ALERT_CARD_META,
  ALERT_CARD_RESOURCE_URI,
  MCP_APP_RESOURCE_MIME,
  applyBrandInjection,
  brandFromEnv,
  buildAlertCard,
} from "./alert-card.js";
import { ALERT_CARD_HTML } from "./generated/alert-card-html.js";
import { getDevicePatches, getSitePatches } from "./patches.js";
import { listActivityLogs } from "./activity-logs.js";
import { listUsers } from "./users.js";
import { findDevicesByMacAddress } from "./mac-lookup.js";
import { listSiteNetworkInterfaces } from "./network-interfaces.js";
import { getEsxiHostAudit } from "./esxi-audit.js";
import {
  applyUntrustedContentMarkers,
  type ToolResultLike,
} from "./untrusted-content.js";

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

export interface DattoCredentials {
  apiKey: string;
  apiSecretKey: string;
  platform: Platform;
}

const VALID_PLATFORMS: Platform[] = [
  "pinotage",
  "merlot",
  "concord",
  "vidal",
  "zinfandel",
  "syrah",
];

/**
 * Resolve a platform string to a valid Platform, defaulting to "concord".
 */
export function resolvePlatform(platform: string | undefined): Platform {
  return platform && VALID_PLATFORMS.includes(platform as Platform)
    ? (platform as Platform)
    : "concord";
}

/**
 * Read credentials from environment variables (stdio / env HTTP mode).
 */
export function getCredentials(): DattoCredentials | null {
  const apiKey = process.env.DATTO_API_KEY || process.env.X_API_KEY;
  const apiSecretKey = process.env.DATTO_API_SECRET || process.env.X_API_SECRET;
  const platformEnv = process.env.DATTO_PLATFORM || "concord";

  if (!apiKey || !apiSecretKey) {
    return null;
  }

  return { apiKey, apiSecretKey, platform: resolvePlatform(platformEnv) };
}

/**
 * Resolve per-request gateway credentials from a header accessor.
 *
 * Works with any transport: pass a getter that returns a (lowercased) header
 * value. Returns `{ creds }` when the required headers are present, or
 * `{ error }` otherwise.
 *
 * Gateway header mapping:
 *   X-Datto-API-Key    -> apiKey
 *   X-Datto-API-Secret -> apiSecretKey
 *   X-Datto-Platform   -> platform (optional, defaults to concord)
 */
export function resolveGatewayCredentials(
  getHeader: (lowerName: string) => string | undefined
): { creds?: DattoCredentials; error?: string } {
  const apiKey = getHeader("x-datto-api-key");
  const apiSecret = getHeader("x-datto-api-secret");
  const platform = getHeader("x-datto-platform");

  if (!apiKey || !apiSecret) {
    return {
      error:
        "Gateway mode requires X-Datto-API-Key and X-Datto-API-Secret headers",
    };
  }

  return {
    creds: {
      apiKey,
      apiSecretKey: apiSecret,
      platform: resolvePlatform(platform),
    },
  };
}

function createClient(creds: DattoCredentials): DattoRmmClient {
  return new DattoRmmClient({
    apiKey: creds.apiKey,
    apiSecretKey: creds.apiSecretKey,
    platform: creds.platform,
  });
}

// ---------------------------------------------------------------------------
// Helper to collect items from async iterator
// ---------------------------------------------------------------------------

async function collectItems<T>(
  iterable: AsyncIterable<T>,
  max: number
): Promise<T[]> {
  const items: T[] = [];
  for await (const item of iterable) {
    items.push(item);
    if (items.length >= max) break;
  }
  return items;
}

// ---------------------------------------------------------------------------
// Hostname lookup helper
// ---------------------------------------------------------------------------

/**
 * Query params for device list endpoints. The Datto RMM API supports
 * server-side hostname filtering (substring match) on both
 * `GET /v2/account/devices` and `GET /v2/site/{siteUid}/devices`. The SDK's
 * typed params only cover pagination, but it forwards extra query params
 * verbatim, so we pass `hostname` through and refine the (already narrowed)
 * result client-side for exact matching.
 */
interface DeviceSearchQuery {
  hostname?: string;
  page?: number;
  max?: number;
}

/**
 * The SDK returns raw Datto RMM API payloads; these runtime field names are
 * not part of the SDK's typed `Device` interface yet.
 */
type RawDevice = Device & {
  online?: boolean;
  lastSeen?: number | string;
  intIpAddress?: string;
  extIpAddress?: string;
  portalUrl?: string;
};

/** Lightweight device summary returned by datto_find_device and datto_find_device_by_mac. */
export interface DeviceMatch {
  uid: string;
  hostname: string;
  siteUid?: string;
  siteName?: string;
  online?: boolean;
  intIpAddress?: string;
  extIpAddress?: string;
  operatingSystem?: string;
  lastSeen?: number | string;
  portalUrl?: string;
}

/**
 * Strips null/empty-string UDF (user-defined field) entries from a device
 * record before it's serialised to the caller.
 *
 * Live sweep (4 Oct 2026) found every device record carries a `udf` object
 * with 300 keys (`udf1`-`udf300`), almost all null — about 2,500 tokens of
 * pure noise per device, meaning `datto_list_devices` with its default
 * max: 50 was returning roughly 125k tokens of nulls alone. Only non-null,
 * non-empty-string UDF values (e.g. a real `udf19` note an RMM policy
 * wrote) carry any information, so this keeps only those. A device with no
 * `udf` object at all, or a non-object `udf`, passes through unchanged.
 */
export function compactUdf(
  device: Record<string, unknown>
): Record<string, unknown> {
  const udf = device?.udf;
  if (typeof udf !== "object" || udf === null) {
    return device;
  }

  const compact: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(udf as Record<string, unknown>)) {
    if (value === null || value === "") continue;
    compact[key] = value;
  }

  return { ...device, udf: compact };
}

/** Shared mapping from a raw SDK `Device` to the lightweight summary both datto_find_device and datto_find_device_by_mac return. */
function toDeviceMatch(device: Device): DeviceMatch {
  const raw = device as RawDevice;
  return {
    uid: device.uid,
    hostname: device.hostname,
    siteUid: device.siteUid,
    siteName: device.siteName,
    online: raw.online ?? raw.isOnline,
    intIpAddress: raw.intIpAddress,
    extIpAddress: raw.extIpAddress,
    operatingSystem: device.operatingSystem,
    lastSeen: raw.lastSeen ?? raw.lastSeenAt,
    portalUrl: raw.portalUrl,
  };
}

export async function findDevicesByHostname(
  client: DattoRmmClient,
  hostname: string,
  options: { siteUid?: string; exactMatch?: boolean; max?: number } = {}
): Promise<DeviceMatch[]> {
  const needle = hostname.trim().toLowerCase();
  const { siteUid, exactMatch = true, max = 25 } = options;

  // One server-filtered page (API page cap: 250) is plenty for a hostname
  // lookup; the API's hostname filter does the heavy lifting server-side.
  const query: DeviceSearchQuery = { hostname: needle, max: 250 };
  const response = siteUid
    ? await client.sites.devices(siteUid, query)
    : await client.account.devices(query);

  return (response.devices ?? [])
    .filter((device) => {
      const candidate = device.hostname?.trim().toLowerCase();
      if (!candidate) return false;
      return exactMatch ? candidate === needle : candidate.includes(needle);
    })
    .slice(0, Math.max(1, max))
    .map(toDeviceMatch);
}

// ---------------------------------------------------------------------------
// Component catalogue
// ---------------------------------------------------------------------------

/**
 * The published `@wyre-ai/node-datto-rmm@1.1.0` `Component` type is a
 * good-faith guess at the `GET /v2/account/components` response shape, not
 * a verified spec. Confirmed live against a real account (2026-09-26,
 * `GET /account/components?max=250`, 250+ components inspected): every
 * component has exactly `id`, `credentialsRequired`, `uid`, `name`,
 * `description`, `categoryCode`, `variables` — there is no `level` or
 * `category` field at all. Datto does not expose a component's security
 * Level over this endpoint (see the tool description for what that means
 * for diagnosing datto_run_quickjob failures). `category` is kept as a
 * defensive fallback in case a differently-configured account or API
 * version ever sends it instead (see `RawDevice` above for the same
 * pattern), but `categoryCode` is what the live API actually returns.
 *
 * The SDK doesn't declare `variables` on `Component` at all, and its shape
 * isn't documented anywhere in the SDK's types, so each entry is read
 * defensively field-by-field in toComponentVariableSummary below.
 */
type RawComponent = Component & {
  categoryCode?: string;
  credentialsRequired?: boolean;
  variables?: unknown[];
};

/**
 * Compact summary of one of a component's expected input variables — what
 * datto_run_quickjob's `variables` map needs to be filled in with to run
 * this component. The SDK doesn't type this shape, so every field is read
 * defensively and only included when present.
 */
export interface ComponentVariableSummary {
  name?: string;
  type?: string;
  defaultValue?: string;
  description?: string;
}

function toComponentVariableSummary(raw: unknown): ComponentVariableSummary {
  const v = (raw ?? {}) as Record<string, unknown>;
  const summary: ComponentVariableSummary = {};
  if (typeof v.name === "string") summary.name = v.name;
  if (typeof v.type === "string") summary.type = v.type;
  const defaultValue = v.defaultValue ?? v.default ?? v.value;
  if (typeof defaultValue === "string") summary.defaultValue = defaultValue;
  if (typeof v.description === "string") summary.description = v.description;
  return summary;
}

/** Component summary returned by datto_list_components. */
export interface ComponentMatch {
  uid: string;
  name: string;
  description?: string;
  categoryCode?: string;
  credentialsRequired?: boolean;
  variables?: ComponentVariableSummary[];
}

function toComponentMatch(component: Component): ComponentMatch {
  const raw = component as RawComponent;
  return {
    uid: component.uid,
    name: component.name,
    description: component.description,
    categoryCode: raw.categoryCode ?? raw.category,
    credentialsRequired: raw.credentialsRequired,
    variables: Array.isArray(raw.variables)
      ? raw.variables.map(toComponentVariableSummary)
      : undefined,
  };
}

// ---------------------------------------------------------------------------
// Quick job payload shape
// ---------------------------------------------------------------------------

/**
 * The correct `POST/PUT .../device/{uid}/quickjob` request body, verified
 * empirically against the live Datto RMM API (2026-09-14). The API rejects
 * the flat shape the published `@wyre-ai/node-datto-rmm@1.1.0` types declare
 * (`{ jobName, componentUid, variables }`) with HTTP 400
 * `{"errorMessage":"Failed to read request"}` — it never parses and no job
 * is created. It requires `componentUid` and `variables` nested under
 * `jobComponent`, with `variables` as an ARRAY of `{name, value}` pairs
 * rather than a key/value map:
 *
 *   { jobName, jobComponent: { componentUid, variables: [{name, value}] } }
 *
 * The SDK's `createQuickJob` forwards the request body verbatim, so this
 * nested shape works at runtime today even though the library's exported
 * `QuickJobRequest` type is still the wrong flat one. A fix to the library
 * itself is pending upstream but not yet published. Once
 * `@wyre-ai/node-datto-rmm` publishes the corrected type, remove this local
 * interface and the `as unknown as QuickJobRequest` cast at the call site
 * below — do NOT "simplify" the payload back to the flat shape, it will
 * start failing against the real API again.
 */
interface QuickJobRequestBody {
  jobName: string;
  jobComponent: {
    componentUid: string;
    variables: { name: string; value: string }[];
  };
}

// ---------------------------------------------------------------------------
// Server factory — creates a fresh server per request (stateless HTTP mode)
// ---------------------------------------------------------------------------

/**
 * The returned server is NOT registered as "the" server anywhere here —
 * callers are responsible for binding it into the per-request `server-ref`
 * AsyncLocalStorage context (via `runWithServerRef` / `bindServerRef`) so
 * elicitation helpers (`utils/elicitation.ts`) resolve the right server
 * even after await gaps. See `utils/server-ref.ts` for why this matters.
 */
export function createMcpServer(credentialOverrides?: DattoCredentials): Server {
  const server = new Server(
    {
      name: "datto-rmm-mcp",
      version: "1.0.0",
    },
    {
      capabilities: {
        tools: {},
        resources: {},
      },
    }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: [
        {
          name: "datto_list_devices",
          description:
            "List all devices in Datto RMM. Can filter by site. To look up a single device by hostname, use datto_find_device instead.",
          inputSchema: {
            type: "object",
            properties: {
              siteUid: {
                type: "string",
                description:
                  "Filter devices by site UID (optional - if omitted, returns all devices)",
              },
              max: {
                type: "number",
                description: "Maximum number of results (default: 50)",
                default: 50,
              },
            },
          },
        },
        {
          name: "datto_find_device",
          description:
            "Find a device by hostname and return its UID plus a lightweight summary. Use this before datto_get_device when the user provides a hostname instead of a UID.",
          inputSchema: {
            type: "object",
            properties: {
              hostname: {
                type: "string",
                description: "Hostname to search for, for example APP-HV-HOST06",
              },
              siteUid: {
                type: "string",
                description:
                  "Optional site UID to narrow the hostname lookup to one site",
              },
              exactMatch: {
                type: "boolean",
                description:
                  "Require an exact (case-insensitive) hostname match. Set to false for partial/substring matching. Defaults to true.",
                default: true,
              },
              max: {
                type: "number",
                description:
                  "Maximum number of matching devices to return (default: 25)",
                default: 25,
              },
            },
            required: ["hostname"],
          },
        },
        {
          name: "datto_get_device",
          description:
            "Get full details for a specific device by its UID. If you only have a hostname, call datto_find_device first to resolve the UID.",
          inputSchema: {
            type: "object",
            properties: {
              deviceUid: {
                type: "string",
                description: "The device UID",
              },
            },
            required: ["deviceUid"],
          },
        },
        {
          name: "datto_list_alerts",
          description: "List open alerts. Can filter by site.",
          inputSchema: {
            type: "object",
            properties: {
              siteUid: {
                type: "string",
                description:
                  "Filter alerts by site UID (optional - if omitted, returns all account alerts)",
              },
              max: {
                type: "number",
                description: "Maximum number of results (default: 50)",
                default: 50,
              },
            },
          },
        },
        {
          name: "datto_get_alert",
          description: "Get details for a specific alert by its UID",
          _meta: ALERT_CARD_META,
          inputSchema: {
            type: "object",
            properties: {
              alertUid: {
                type: "string",
                description: "The alert UID",
              },
            },
            required: ["alertUid"],
          },
        },
        {
          name: "datto_resolve_alert",
          description: "Resolve an alert by its UID",
          _meta: ALERT_CARD_META,
          inputSchema: {
            type: "object",
            properties: {
              alertUid: {
                type: "string",
                description: "The alert UID to resolve",
              },
            },
            required: ["alertUid"],
          },
        },
        {
          name: "datto_list_sites",
          description: "List all sites in the account",
          inputSchema: {
            type: "object",
            properties: {
              max: {
                type: "number",
                description: "Maximum number of results (default: 50)",
                default: 50,
              },
            },
          },
        },
        {
          name: "datto_get_site",
          description: "Get details for a specific site by its UID",
          inputSchema: {
            type: "object",
            properties: {
              siteUid: {
                type: "string",
                description: "The site UID",
              },
            },
            required: ["siteUid"],
          },
        },
        {
          name: "datto_list_components",
          description:
            "List components (the scripts/monitors available to run as quick jobs) in the account, optionally filtered by a case-insensitive substring of the name. Use this to find a componentUid for datto_run_quickjob — otherwise there's no way to get one short of the Datto RMM web UI. Each result's `variables` lists what datto_run_quickjob's `variables` map needs to be filled in with to run that component. A quickjob HTTP 500 usually means the API user's security role is below the component's Level (Datto returns 500 where 403 belongs). The API does not expose component Level; check it in the RMM web UI under the component's settings before blaming the payload.",
          inputSchema: {
            type: "object",
            properties: {
              name: {
                type: "string",
                description:
                  'Case-insensitive substring filter on component name, e.g. "disk" or "cleanup". Applied across every page of the account\'s component catalogue before truncating to max, so a match on a later page isn\'t missed.',
              },
              max: {
                type: "number",
                description: "Maximum number of results (default: 50)",
                default: 50,
              },
            },
          },
        },
        {
          name: "datto_run_quickjob",
          description:
            "Run a quick job on a device. Returns a job UID — pass it to datto_get_job, datto_get_job_components, datto_get_job_results, datto_get_job_stdout, and datto_get_job_stderr to check the job's status and retrieve its output, since this call itself is fire-and-forget.",
          inputSchema: {
            type: "object",
            properties: {
              deviceUid: {
                type: "string",
                description: "The device UID to run the job on",
              },
              jobName: {
                type: "string",
                description: "Name for the quick job",
              },
              componentUid: {
                type: "string",
                description: "UID of the component to run",
              },
              variables: {
                type: "object",
                description: "Variables to pass to the job (key-value pairs)",
                additionalProperties: { type: "string" },
              },
            },
            required: ["deviceUid", "jobName", "componentUid"],
          },
        },
        {
          name: "datto_get_job",
          description:
            "Get status and details for a quick job by its UID (e.g. queued/running/completed, device count, timestamps). Use this after datto_run_quickjob to check whether the job finished and how it went.",
          inputSchema: {
            type: "object",
            properties: {
              jobUid: {
                type: "string",
                description: "The job UID, returned by datto_run_quickjob",
              },
            },
            required: ["jobUid"],
          },
        },
        {
          name: "datto_get_job_components",
          description:
            "Get the components (scripts/actions and their variables) that make up a quick job",
          inputSchema: {
            type: "object",
            properties: {
              jobUid: {
                type: "string",
                description: "The job UID",
              },
            },
            required: ["jobUid"],
          },
        },
        {
          name: "datto_get_job_results",
          description:
            "Get the result of a quick job on one specific device — status, exit code, timing, and error message if it failed. Use datto_get_job first if you need to find which devices the job ran on.",
          inputSchema: {
            type: "object",
            properties: {
              jobUid: {
                type: "string",
                description: "The job UID",
              },
              deviceUid: {
                type: "string",
                description: "The device UID to get the job result for",
              },
            },
            required: ["jobUid", "deviceUid"],
          },
        },
        {
          name: "datto_get_job_stdout",
          description:
            "Get the captured stdout output of a quick job on a specific device. Use this to diagnose what a script actually printed when a quick job's outcome is unclear.",
          inputSchema: {
            type: "object",
            properties: {
              jobUid: {
                type: "string",
                description: "The job UID",
              },
              deviceUid: {
                type: "string",
                description: "The device UID",
              },
            },
            required: ["jobUid", "deviceUid"],
          },
        },
        {
          name: "datto_get_job_stderr",
          description:
            "Get the captured stderr output of a quick job on a specific device. Use this to diagnose why a quick job failed.",
          inputSchema: {
            type: "object",
            properties: {
              jobUid: {
                type: "string",
                description: "The job UID",
              },
              deviceUid: {
                type: "string",
                description: "The device UID",
              },
            },
            required: ["jobUid", "deviceUid"],
          },
        },
        {
          name: "datto_get_device_audit",
          description:
            "Get audit data for a device (hardware, software, OS information)",
          inputSchema: {
            type: "object",
            properties: {
              deviceUid: {
                type: "string",
                description: "The device UID",
              },
              auditType: {
                type: "string",
                enum: ["full", "software"],
                description:
                  "Type of audit: 'full' for complete audit or 'software' for software inventory only",
                default: "full",
              },
            },
            required: ["deviceUid"],
          },
        },
        {
          name: "datto_get_device_patches",
          description:
            "Get Windows patch installation status for a device - per-patch installed/missing/pending status, severity, reboot requirement, and KB article",
          inputSchema: {
            type: "object",
            properties: {
              deviceUid: {
                type: "string",
                description: "The device UID",
              },
            },
            required: ["deviceUid"],
          },
        },
        {
          name: "datto_get_site_patches",
          description:
            "Get Windows patch installation status across all devices in a site",
          inputSchema: {
            type: "object",
            properties: {
              siteUid: {
                type: "string",
                description: "The site UID",
              },
            },
            required: ["siteUid"],
          },
        },
        {
          name: "datto_list_activity_logs",
          description:
            "RMM activity log: who remotely took over or screen-controlled a device and when, web remote PowerShell sessions, file transfers, jobs created/deployed, console logins, and patch runs. For anything older than 24 hours, pass `from` explicitly - by default this only looks back 24 hours. Useful entity/category/action filters for \"who was on that machine\": DEVICE/remote/jrto (remote takeover - details include remote_session.type, start/end dates, user, source IP, device.hostname), USER/web.remote/rto (Web Remote), USER/account/login (console logins). Also covers DEVICE/job/deployment, USER/job/create, DEVICE/patch/audit, DEVICE/patch/run. Pass `cursor` (from a prior call's `nextCursor`) to page forward.",
          inputSchema: {
            type: "object",
            properties: {
              from: {
                type: "string",
                description:
                  "Start of the time range (any format Date can parse). Default: 24 hours ago. Required for anything older than that.",
              },
              until: {
                type: "string",
                description: "End of the time range (any format Date can parse).",
              },
              entities: {
                type: "array",
                items: { type: "string", enum: ["device", "user"] },
                description: "Filter by entity type.",
              },
              categories: {
                type: "array",
                items: { type: "string" },
                description: 'Filter by category, e.g. "remote", "job", "account", "patch".',
              },
              actions: {
                type: "array",
                items: { type: "string" },
                description: 'Filter by action, e.g. "jrto", "rto", "login", "deployment".',
              },
              siteIds: {
                type: "array",
                items: { type: "number" },
                description: "Filter by site ID.",
              },
              userIds: {
                type: "array",
                items: { type: "number" },
                description: "Filter by user ID.",
              },
              searchQuery: {
                type: "string",
                description:
                  'Lucene-style query, e.g. \'data.filter_id : "filterId" AND device.hostname : "hostname"\'.',
              },
              order: {
                type: "string",
                enum: ["asc", "desc"],
                description: "Sort order by creation date. Default: desc.",
                default: "desc",
              },
              size: {
                type: "number",
                description: "Page size, clamped to 1-250. Default: 100.",
                default: 100,
              },
              cursor: {
                type: "string",
                description: "Opaque pagination cursor from a prior response's nextCursor.",
              },
            },
          },
        },
        {
          name: "datto_list_users",
          description:
            "RMM console user accounts: who can log in to Datto RMM and remotely access managed devices, with last access and disabled state.",
          inputSchema: {
            type: "object",
            properties: {},
          },
        },
        {
          name: "datto_find_device_by_mac",
          description:
            "Find device(s) by MAC address. Accepts common formats (aa:bb:cc:dd:ee:ff, aa-bb-cc-dd-ee-ff, aabb.ccdd.eeff, or bare hex) and normalises automatically. Returns a lightweight summary per match, same shape as datto_find_device.",
          inputSchema: {
            type: "object",
            properties: {
              macAddress: {
                type: "string",
                description: "MAC address in any common format",
              },
            },
            required: ["macAddress"],
          },
        },
        {
          name: "datto_list_site_network_interfaces",
          description:
            "IP and MAC addresses for every device in a site - answers 'what is at 10.x.x.x at this client'.",
          inputSchema: {
            type: "object",
            properties: {
              siteUid: {
                type: "string",
                description: "The site UID",
              },
              max: {
                type: "number",
                description: "Maximum number of devices to return (default: 250)",
                default: 250,
              },
            },
            required: ["siteUid"],
          },
        },
        {
          name: "datto_get_esxi_host_audit",
          description:
            "Get audit data for a VMware ESXi host (system info, guests, processors, NICs, memory, datastores). Only works for devices that are VMware ESXi hosts - any other device returns an error.",
          inputSchema: {
            type: "object",
            properties: {
              deviceUid: {
                type: "string",
                description: "The device UID",
              },
            },
            required: ["deviceUid"],
          },
        },
      ],
    };
  });

  // MCP Apps (SEP-1865): the ui:// alert card is static HTML embedded at
  // build time (src/generated/alert-card-html.ts), so it serves identically
  // from stdio, Node HTTP, and the fs-less Cloudflare Workers runtime.
  server.setRequestHandler(ListResourcesRequestSchema, async () => {
    return {
      resources: [
        {
          uri: ALERT_CARD_RESOURCE_URI,
          name: "Datto RMM Alert Card",
          description: "Interactive MCP Apps card rendering a Datto RMM alert",
          mimeType: MCP_APP_RESOURCE_MIME,
        },
      ],
    };
  });

  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const { uri } = request.params;
    if (uri !== ALERT_CARD_RESOURCE_URI) {
      throw new Error(`Unknown resource: ${uri}`);
    }
    return {
      contents: [
        {
          uri,
          mimeType: MCP_APP_RESOURCE_MIME,
          // The card ships neutral; operators brand it at serve time via
          // MCP_BRAND_* env vars (no vars = HTML served unchanged).
          text: applyBrandInjection(ALERT_CARD_HTML, brandFromEnv()),
        },
      ],
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const creds = credentialOverrides ?? getCredentials();

    if (!creds) {
      return {
        content: [
          {
            type: "text",
            text: "Error: No API credentials provided. Please configure your Datto RMM API key and secret via DATTO_API_KEY and DATTO_API_SECRET environment variables.",
          },
        ],
        isError: true,
      };
    }

    const client = createClient(creds);

    // Every branch below returns raw tool output; wrapping happens once,
    // after this IIFE settles, via applyUntrustedContentMarkers — see
    // untrusted-content.ts for why and for which tools.
    const result = await (async (): Promise<ToolResultLike> => {
      try {
      switch (name) {
        case "datto_list_devices": {
          const params = args as { siteUid?: string; max?: number };
          const max = params.max || 50;
          let siteUid = params.siteUid;

          // If no site filter, ask the user if they want to narrow by site
          if (!siteUid) {
            const siteFilter = await elicitSelection(
              "Listing all devices across all sites can return a large result set. Would you like to filter by a specific site?",
              "site",
              [
                { value: "__all__", label: "All sites (no filter)" },
                { value: "__enter__", label: "Enter a site UID manually" },
              ]
            );
            if (siteFilter === "__enter__") {
              const { elicitText } = await import("./utils/elicitation.js");
              const enteredUid = await elicitText(
                "Enter the site UID to filter devices by.",
                "siteUid",
                "The site UID from Datto RMM"
              );
              if (enteredUid) {
                siteUid = enteredUid;
              }
            }
          }

          let devices;
          if (siteUid) {
            devices = await collectItems(client.sites.devicesAll(siteUid), max);
          } else {
            devices = await collectItems(client.account.devicesAll(), max);
          }

          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  (devices ?? []).map((d) =>
                    compactUdf(d as unknown as Record<string, unknown>)
                  ),
                  null,
                  2
                ),
              },
            ],
          };
        }

        case "datto_find_device": {
          const {
            hostname,
            siteUid,
            exactMatch = true,
            max = 25,
          } = args as {
            hostname: string;
            siteUid?: string;
            exactMatch?: boolean;
            max?: number;
          };

          if (!hostname?.trim()) {
            return {
              content: [
                { type: "text", text: "Error: hostname must not be empty" },
              ],
              isError: true,
            };
          }

          const devices = await findDevicesByHostname(client, hostname, {
            siteUid,
            exactMatch,
            max,
          });

          // Explicit not-found error instead of an empty success — empty
          // successes invite downstream LLM hallucination.
          if (devices.length === 0) {
            const scope = siteUid ? ` in site ${siteUid}` : "";
            const hint = exactMatch
              ? " Retry with exactMatch: false for partial matching, or verify the hostname with datto_list_devices."
              : " Verify the hostname with datto_list_devices.";
            return {
              content: [
                {
                  type: "text",
                  text: `No devices found matching hostname "${hostname}"${scope}.${hint}`,
                },
              ],
              isError: true,
            };
          }

          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  { count: devices.length, devices },
                  null,
                  2
                ),
              },
            ],
          };
        }

        case "datto_get_device": {
          const { deviceUid } = args as { deviceUid: string };
          const device = await client.devices.get(deviceUid);
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  device
                    ? compactUdf(device as unknown as Record<string, unknown>)
                    : {},
                  null,
                  2
                ),
              },
            ],
          };
        }

        case "datto_list_alerts": {
          const params = args as { siteUid?: string; max?: number };
          const max = params.max || 50;
          let siteUid = params.siteUid;

          // If no site filter, ask the user if they want to narrow by site
          if (!siteUid) {
            const siteFilter = await elicitSelection(
              "Listing all open alerts can return many results. Would you like to filter by a specific site?",
              "site",
              [
                { value: "__all__", label: "All sites (no filter)" },
                { value: "__enter__", label: "Enter a site UID manually" },
              ]
            );
            if (siteFilter === "__enter__") {
              const { elicitText } = await import("./utils/elicitation.js");
              const enteredUid = await elicitText(
                "Enter the site UID to filter alerts by.",
                "siteUid",
                "The site UID from Datto RMM"
              );
              if (enteredUid) {
                siteUid = enteredUid;
              }
            }
          }

          let alerts;
          if (siteUid) {
            alerts = await collectItems(client.sites.alertsOpenAll(siteUid), max);
          } else {
            alerts = await collectItems(client.account.alertsOpenAll(), max);
          }

          return {
            content: [
              { type: "text", text: JSON.stringify(alerts ?? [], null, 2) },
            ],
          };
        }

        case "datto_get_alert": {
          const { alertUid } = args as { alertUid: string };
          const alert = await client.alerts.get(alertUid);
          // MCP Apps: attach the normalized payload the ui:// alert card
          // renders from. Best-effort — a null card just means no UI surface.
          const card = buildAlertCard(alert);
          const payload = card ? { ...alert, _card: card } : alert;
          return {
            content: [
              { type: "text", text: JSON.stringify(payload ?? {}, null, 2) },
            ],
          };
        }

        case "datto_resolve_alert": {
          const { alertUid } = args as { alertUid: string };
          const result = await client.alerts.resolve(alertUid);
          return {
            content: [
              { type: "text", text: JSON.stringify(result ?? {}, null, 2) },
            ],
          };
        }

        case "datto_list_sites": {
          const params = args as { max?: number };
          const max = params.max || 50;
          const sites = await collectItems(client.account.sitesAll(), max);
          return {
            content: [
              { type: "text", text: JSON.stringify(sites ?? [], null, 2) },
            ],
          };
        }

        case "datto_get_site": {
          const { siteUid } = args as { siteUid: string };
          const site = await client.sites.get(siteUid);
          return {
            content: [{ type: "text", text: JSON.stringify(site, null, 2) }],
          };
        }

        case "datto_list_components": {
          const params = args as { name?: string; max?: number };
          const max = params.max || 50;
          const nameFilter = params.name?.trim().toLowerCase();

          let matches: Component[];
          let totalMatched: number;

          if (nameFilter) {
            // Filter across every page before truncating — otherwise a
            // match on (say) page 5 of the catalogue would be missed just
            // because non-matching components on earlier pages filled max.
            const allMatches: Component[] = [];
            for await (const component of client.account.componentsAll()) {
              if (component.name?.toLowerCase().includes(nameFilter)) {
                allMatches.push(component);
              }
            }
            totalMatched = allMatches.length;
            matches = allMatches.slice(0, max);
          } else {
            matches = await collectItems(client.account.componentsAll(), max);
            totalMatched = matches.length;
          }

          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    totalMatched,
                    returned: matches.length,
                    components: matches.map(toComponentMatch),
                  },
                  null,
                  2
                ),
              },
            ],
          };
        }

        case "datto_run_quickjob": {
          const { deviceUid, jobName, componentUid, variables } = args as {
            deviceUid: string;
            jobName: string;
            componentUid: string;
            variables?: Record<string, string>;
          };

          // Public inputSchema keeps `variables` as a friendly key/value map
          // (a nicer calling convention for an LLM) — convert to the array
          // of {name, value} pairs the live API actually requires. See the
          // QuickJobRequestBody comment above for why this nesting exists.
          const jobRequest: QuickJobRequestBody = {
            jobName,
            jobComponent: {
              componentUid,
              variables: Object.entries(variables ?? {}).map(
                ([name, value]) => ({ name, value })
              ),
            },
          };

          const result = await client.devices.createQuickJob(
            deviceUid,
            // The published library type for this parameter is the wrong
            // flat shape — see the QuickJobRequestBody comment above.
            jobRequest as unknown as QuickJobRequest
          );
          return {
            content: [
              { type: "text", text: JSON.stringify(result ?? {}, null, 2) },
            ],
          };
        }

        case "datto_get_job": {
          const { jobUid } = args as { jobUid: string };
          const job = await client.jobs.get(jobUid);
          return {
            content: [
              { type: "text", text: JSON.stringify(job ?? {}, null, 2) },
            ],
          };
        }

        case "datto_get_job_components": {
          const { jobUid } = args as { jobUid: string };
          const components = await client.jobs.components(jobUid);
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(components ?? [], null, 2),
              },
            ],
          };
        }

        case "datto_get_job_results": {
          const { jobUid, deviceUid } = args as {
            jobUid: string;
            deviceUid: string;
          };
          const result = await client.jobs.results(jobUid, deviceUid);
          return {
            content: [
              { type: "text", text: JSON.stringify(result ?? {}, null, 2) },
            ],
          };
        }

        case "datto_get_job_stdout": {
          const { jobUid, deviceUid } = args as {
            jobUid: string;
            deviceUid: string;
          };
          const stdout = await client.jobs.stdout(jobUid, deviceUid);
          return {
            content: [
              { type: "text", text: JSON.stringify(stdout ?? "", null, 2) },
            ],
          };
        }

        case "datto_get_job_stderr": {
          const { jobUid, deviceUid } = args as {
            jobUid: string;
            deviceUid: string;
          };
          const stderr = await client.jobs.stderr(jobUid, deviceUid);
          return {
            content: [
              { type: "text", text: JSON.stringify(stderr ?? "", null, 2) },
            ],
          };
        }

        case "datto_get_device_audit": {
          const { deviceUid, auditType = "full" } = args as {
            deviceUid: string;
            auditType?: "full" | "software";
          };

          let audit;
          if (auditType === "software") {
            audit = await client.audit.deviceSoftware(deviceUid);
          } else {
            audit = await client.audit.device(deviceUid);
          }

          return {
            content: [
              { type: "text", text: JSON.stringify(audit ?? {}, null, 2) },
            ],
          };
        }

        // Not wrapped by the SDK yet (see src/patches.ts's header comment) -
        // these two call Datto RMM's v2 patch endpoints directly rather than
        // through `client`.
        case "datto_get_device_patches": {
          const { deviceUid } = args as { deviceUid: string };
          const result = await getDevicePatches(creds, deviceUid);
          return {
            content: [
              { type: "text", text: JSON.stringify(result ?? {}, null, 2) },
            ],
          };
        }

        case "datto_get_site_patches": {
          const { siteUid } = args as { siteUid: string };
          const result = await getSitePatches(creds, siteUid);
          return {
            content: [
              { type: "text", text: JSON.stringify(result ?? {}, null, 2) },
            ],
          };
        }

        case "datto_list_activity_logs": {
          const params = args as {
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
          };
          const result = await listActivityLogs(creds, params);
          return {
            content: [
              { type: "text", text: JSON.stringify(result, null, 2) },
            ],
          };
        }

        case "datto_list_users": {
          const result = await listUsers(creds);
          return {
            content: [
              { type: "text", text: JSON.stringify(result, null, 2) },
            ],
          };
        }

        case "datto_find_device_by_mac": {
          const { macAddress } = args as { macAddress: string };
          const devices = await findDevicesByMacAddress(creds, macAddress);
          const matches = (devices ?? []).map(toDeviceMatch);

          if (matches.length === 0) {
            return {
              content: [
                {
                  type: "text",
                  text: `No devices found with MAC address "${macAddress}".`,
                },
              ],
              isError: true,
            };
          }

          return {
            content: [
              {
                type: "text",
                text: JSON.stringify({ count: matches.length, devices: matches }, null, 2),
              },
            ],
          };
        }

        case "datto_list_site_network_interfaces": {
          const { siteUid, max } = args as { siteUid: string; max?: number };
          const result = await listSiteNetworkInterfaces(creds, siteUid, max);
          return {
            content: [
              { type: "text", text: JSON.stringify(result, null, 2) },
            ],
          };
        }

        case "datto_get_esxi_host_audit": {
          const { deviceUid } = args as { deviceUid: string };
          const audit = await getEsxiHostAudit(creds, deviceUid);
          return {
            content: [
              { type: "text", text: JSON.stringify(audit ?? {}, null, 2) },
            ],
          };
        }

        default:
          return {
            content: [{ type: "text", text: `Unknown tool: ${name}` }],
            isError: true,
          };
      }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return {
          content: [{ type: "text", text: `Error: ${message}` }],
          isError: true,
        };
      }
    })();

    return applyUntrustedContentMarkers(name, result);
  });

  return server;
}
