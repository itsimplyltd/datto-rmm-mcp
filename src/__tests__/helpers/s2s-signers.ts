/**
 * TEST HELPERS ONLY. Ports of cred-router's signers (itsimplyltd/MCP-Gateway
 * cred-router/src/s2sV3.js `s2sHeaderV3` / `canonicalV3`, and index.js `s2sHeader`)
 * so the HTTP tests sign requests the way the gateway does.
 */
import { createHash, createHmac, randomBytes } from "node:crypto";

const sha256hex = (v: Buffer | string): string => createHash("sha256").update(v).digest("hex");

/** Legacy v1 header, as cred-router's s2sHeader(). */
export function legacyHeader(secret: string, t: number = Math.floor(Date.now() / 1000)): string {
  return `t=${t},v1=${createHmac("sha256", secret).update(`t=${t}`).digest("hex")}`;
}

/** v3 header over the given outgoing headers (all of them are signed, as the gateway does). */
export function v3Header(
  secret: string,
  o: { aud: string; method?: string; path?: string; body?: string; headers?: Record<string, string>; t?: number; n?: string },
): string {
  const t = o.t ?? Math.floor(Date.now() / 1000);
  const n = o.n ?? randomBytes(16).toString("hex");
  const entries = Object.entries(o.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v] as const);
  const names = entries.map(([k]) => k).sort();
  const byName = new Map(entries);
  const sh = names.join(";");
  const lines = [
    "ITSL-S2S-v3",
    `t=${t}`,
    `n=${n}`,
    `aud=${o.aud}`,
    `m=${(o.method ?? "POST").toUpperCase()}`,
    `p=${o.path ?? "/mcp"}`,
    `b=${sha256hex(Buffer.from(o.body ?? "", "utf8"))}`,
    `sh=${sh}`,
    ...names.map((k) => `${k}:${sha256hex(Buffer.from(byName.get(k)!, "utf8"))}`),
  ];
  const v3 = createHmac("sha256", secret).update(lines.join("\n"), "utf8").digest("hex");
  return `t=${t},n=${n},sh=${sh},v3=${v3}`;
}
