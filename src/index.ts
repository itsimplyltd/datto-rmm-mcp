#!/usr/bin/env node
/**
 * Datto RMM MCP Server
 *
 * This MCP server provides tools for interacting with Datto RMM API.
 * It accepts credentials via environment variables from the MCP Gateway.
 * Supports both stdio (default) and HTTP (StreamableHTTP) transports.
 */

import { createServer, IncomingMessage, ServerResponse, Server as HttpServer } from "node:http";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  createMcpServer,
  resolveGatewayCredentials,
  type DattoCredentials,
} from "./mcp-server.js";
import { runWithServerRef, bindServerRef } from "./utils/server-ref.js";
import { verifyS2sHeader } from "./s2s-verify.js";
import {
  NonceCache,
  ReportRateLimiter,
  assertRequireSignedHeaders,
  effectiveMinVersion,
  handleGatewayRequest,
  type GatewayLogger,
} from "./itsl/s2s-v3.js";
import { installRedirectGuard } from "./redirect-guard.js";

// ---------------------------------------------------------------------------
// S2S v3 (phase A: accept legacy v1 and v3).
//
// Legacy floor 1: today's verifier (s2s-verify.ts) is v1 and is accepted.
// ITSL_S2S_MIN_VERSION raises the minimum (3 = v3 only); it can never lower it.
// Phase B: the gateway starts sending v3. Phase C: ITSL_S2S_MIN_VERSION=3.
// The nonce cache is per process: it must run as ONE replica before min 3.
// ---------------------------------------------------------------------------

/** Audience cred-router signs for this vendor (finishSignedProxyRequest default: the vendor id). */
const S2S_AUDIENCE = "datto";
const S2S_FLOOR = 1;
const MIN_S2S_SECRET_LENGTH = 32;

/**
 * Every header this backend reads for credentials or the vendor platform and
 * that cred-router sets. If present on a v3 request it must be signed.
 * (X-Mcp-User-Upn is set by cred-router but never read here, so it is not listed.)
 */
const REQUIRE_SIGNED_HEADERS = ["x-datto-api-key", "x-datto-api-secret", "x-datto-platform"];
assertRequireSignedHeaders(REQUIRE_SIGNED_HEADERS);

/** One per process; v3 nonces are single-use inside the skew window. */
const nonceCache = new NonceCache();
const reportRateLimiter = new ReportRateLimiter();
const failureLimiter = new ReportRateLimiter();

function logLine(level: string, msg: string, meta?: Record<string, unknown>): void {
  console.error(JSON.stringify({ ts: new Date().toISOString(), level, msg, ...meta }));
}

const logger: GatewayLogger = {
  warn: (msg, meta) => logLine("warn", msg, meta),
  error: (msg, meta) => logLine("error", msg, meta),
};

/** HTTP mode refuses to start without a real S2S secret. Never logs the secret or its length. */
function resolveHttpS2sSecret(): string {
  const secret = process.env.CONDUIT_S2S_SECRET ?? "";
  if (secret.length < MIN_S2S_SECRET_LENGTH) {
    logLine(
      "error",
      "Refusing to start HTTP server: CONDUIT_S2S_SECRET must be set to at least 32 characters (an empty secret would accept unauthenticated /mcp requests)."
    );
    process.exit(1);
  }
  return secret;
}

// ---------------------------------------------------------------------------
// Transport: stdio (default)
// ---------------------------------------------------------------------------

async function startStdioTransport(): Promise<void> {
  const server = createMcpServer();
  // stdio is single-session (one process = one caller), so there is no
  // concurrent tenant to isolate from — bind once for the process
  // lifetime rather than per-request. See utils/server-ref.ts.
  bindServerRef(server);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Datto RMM MCP server running on stdio");
}

// ---------------------------------------------------------------------------
// Transport: HTTP (StreamableHTTPServerTransport)
// ---------------------------------------------------------------------------

let httpServer: HttpServer | undefined;

async function startHttpTransport(): Promise<void> {
  const port = parseInt(process.env.MCP_HTTP_PORT || "8080", 10);
  const host = process.env.MCP_HTTP_HOST || "0.0.0.0";
  const authMode = process.env.AUTH_MODE || "env";
  const isGatewayMode = authMode === "gateway";
  const s2sSecret = resolveHttpS2sSecret();
  // Raw, unvalidated: anything that is not an integer 1..3 is treated as 3 (a typo can only tighten).
  const minVersion = Number(process.env.ITSL_S2S_MIN_VERSION ?? String(S2S_FLOOR));
  const effectiveMin = effectiveMinVersion(S2S_FLOOR, minVersion);
  logLine("info", "S2S v3 configuration", {
    effectiveMinVersion: effectiveMin,
    headerRule: effectiveMin === 3 ? "enforced" : "report",
    audience: S2S_AUDIENCE,
  });

  httpServer = createServer((req: IncomingMessage, res: ServerResponse) => {
    // Path only, no query: the v3 check separately requires the raw target to be exactly /mcp.
    const rawTarget = req.url || "/";
    const queryAt = rawTarget.indexOf("?");
    const pathname = queryAt === -1 ? rawTarget : rawTarget.slice(0, queryAt);

    // Health endpoint - no auth required
    if (pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        status: "ok",
        transport: "http",
        authMode: isGatewayMode ? "gateway" : "env",
        timestamp: new Date().toISOString(),
      }));
      return;
    }

    // MCP endpoint — stateless: fresh server + transport per request
    if (pathname === "/mcp") {
      // The shared wrapper runs the S2S check FIRST, reads the body once and never
      // rejects: an aborted upload or a throwing handler ends that request only.
      void handleGatewayRequest(
        req,
        res,
        {
          secret: s2sSecret,
          aud: S2S_AUDIENCE,
          floor: S2S_FLOOR,
          minVersion,
          verifyLegacy: (headerValue) => (verifyS2sHeader(headerValue, s2sSecret) ? 1 : 0),
          nonceCache,
          reportLimiter: reportRateLimiter,
          failureLimiter,
          logger,
          requireSignedHeaders: REQUIRE_SIGNED_HEADERS,
        },
        async ({ parsedBody }) => {
          // Only POST is supported in stateless mode
          if (req.method !== "POST") {
            res.writeHead(405, { "Content-Type": "application/json" });
            res.end(JSON.stringify({
              jsonrpc: "2.0",
              error: { code: -32000, message: "Method not allowed" },
              id: null,
            }));
            return;
          }

          // In gateway mode, extract credentials from headers and pass directly
          // to avoid process.env race conditions under concurrent load
          let gatewayCredentials: DattoCredentials | undefined;
          if (isGatewayMode) {
            const { creds, error } = resolveGatewayCredentials(
              (name) => req.headers[name] as string | undefined
            );
            if (error) {
              res.writeHead(401, { "Content-Type": "application/json" });
              res.end(JSON.stringify({
                error: "Missing credentials",
                message: error,
                required: ["X-Datto-API-Key", "X-Datto-API-Secret"],
              }));
              return;
            }
            gatewayCredentials = creds;
          }

          // Stateless: create fresh server + transport for each request
          const server = createMcpServer(gatewayCredentials);
          const transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: undefined,
            enableJsonResponse: true,
          });

          res.on("close", () => {
            transport.close();
            server.close();
          });

          // Bind this request's server into the per-request async context (not
          // a module-level global) so elicitation helpers resolve *this*
          // server/transport even after await gaps, and never a concurrent
          // request's — see utils/server-ref.ts. The whole connect/handleRequest
          // chain, including the catch, must stay inside this callback so the
          // bound context survives every await gap it spans.
          await runWithServerRef(server, async () => {
            try {
              await server.connect(transport as unknown as Transport);
              // The body was consumed for the signature check, so hand it over parsed.
              await transport.handleRequest(req, res, parsedBody);
            } catch (err) {
              console.error("MCP transport error:", err);
              if (!res.headersSent) {
                res.writeHead(500, { "Content-Type": "application/json" });
                res.end(JSON.stringify({
                  jsonrpc: "2.0",
                  error: { code: -32603, message: "Internal error" },
                  id: null,
                }));
              }
            }
          });
        },
      );
      return;
    }

    // 404 for everything else, before any auth
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found", endpoints: ["/mcp", "/health"] }));
  });

  await new Promise<void>((resolve) => {
    httpServer!.listen(port, host, () => {
      console.error(`Datto RMM MCP server listening on http://${host}:${port}/mcp`);
      console.error(`Health check available at http://${host}:${port}/health`);
      console.error(`Authentication mode: ${isGatewayMode ? "gateway (header-based)" : "env (environment variables)"}`);
      resolve();
    });
  });
}

// ---------------------------------------------------------------------------
// Graceful shutdown
// ---------------------------------------------------------------------------

function setupShutdownHandlers(): void {
  const shutdown = async () => {
    console.error("Shutting down Datto RMM MCP server...");
    if (httpServer) {
      await new Promise<void>((resolve, reject) => {
        httpServer!.close((err) => (err ? reject(err) : resolve()));
      });
    }
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  // Vendor redirects must fail closed so credentials never follow a 3xx to another host.
  installRedirectGuard();
  setupShutdownHandlers();

  const transportType = process.env.MCP_TRANSPORT || "stdio";

  if (transportType === "http") {
    await startHttpTransport();
  } else {
    await startStdioTransport();
  }
}

main().catch(console.error);
