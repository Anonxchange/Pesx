/**
 * Volatile, module-scoped holder for short-lived secrets (recovery phrases).
 *
 * Kept OUTSIDE the React tree on purpose: nothing here is in useState,
 * useRef, props, context, or a React Query key/cache, so React DevTools and
 * query devtools cannot enumerate it. Callers hold only a non-secret id.
 *
 * Every secret has a hard TTL and is wiped on unmount, close, confirmation,
 * logout, and account switch (wipeAllVolatileSecrets).
 */
const secrets = new Map<string, string>();
const timers = new Map<string, ReturnType<typeof setTimeout>>();

const DEFAULT_TTL_MS = 5 * 60_000;

export function setVolatileSecret(
  id: string,
  value: string,
  opts: { ttlMs?: number; onExpire?: () => void } = {},
): void {
  wipeVolatileSecret(id);
  secrets.set(id, value);
  timers.set(
    id,
    setTimeout(() => {
      wipeVolatileSecret(id);
      opts.onExpire?.();
    }, opts.ttlMs ?? DEFAULT_TTL_MS),
  );
}

export function getVolatileSecret(id: string): string {
  return secrets.get(id) ?? "";
}

export function wipeVolatileSecret(id: string): void {
  const t = timers.get(id);
  if (t) clearTimeout(t);
  timers.delete(id);
  // JS strings are immutable so bytes cannot be zeroed; dropping the only
  // reference is the best available.
  secrets.set(id, "");
  secrets.delete(id);
}

export function wipeAllVolatileSecrets(): void {
  for (const id of Array.from(secrets.keys())) wipeVolatileSecret(id);
}
