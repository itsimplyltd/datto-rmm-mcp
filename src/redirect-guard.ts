/**
 * Fail-closed redirects for every outbound vendor request.
 *
 * Node's fetch follows redirects by default and re-sends the Authorization
 * header to the redirect target when the origin matches, and a vendor redirect
 * must never carry our Datto credentials anywhere else. Our own fetch calls
 * (rmm-api.ts) pass `redirect: "error"` explicitly. The vendored
 * @wyre-ai/node-datto-rmm SDK calls the global fetch without that option, so
 * the container entry point installs this wrapper, which defaults the option
 * to "error" whenever the caller did not choose one.
 */

const GUARDED = Symbol.for("itsl.redirectGuard");

type GuardedFetch = typeof fetch & { [GUARDED]?: true };

export function installRedirectGuard(): void {
  const current = globalThis.fetch as GuardedFetch;
  if (typeof current !== "function" || current[GUARDED]) return;
  const guarded: GuardedFetch = ((input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    // An explicit choice by the caller is respected; otherwise fail closed (this also overrides a Request object's default "follow").
    if (init?.redirect !== undefined) return current(input, init);
    return current(input, { ...init, redirect: "error" });
  }) as GuardedFetch;
  guarded[GUARDED] = true;
  globalThis.fetch = guarded;
}
