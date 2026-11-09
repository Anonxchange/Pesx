/**
 * Server-side wallet-unlock rate limiter.
 *
 * Wraps a local decryption attempt with two RPC calls:
 *   1. `checkUnlockAllowed(userId)` BEFORE attempting decrypt — throws
 *      `WalletLockedError` if the account is currently locked out.
 *   2. `reportUnlockAttempt(userId, success)` AFTER the attempt — clears
 *      the counter on success or escalates the lockout on failure.
 *
 * Failures are escalated server-side (4 → 30s, 5 → 1m, 6 → 5m, 7 → 30m,
 * 8+ → 24h). A stolen vault blob therefore cannot be brute-forced offline
 * via the app UI even if the attacker also has the user's session cookie.
 *
 * When the DB is unreachable an in-memory fallback counter enforces a
 * local lockout so DB outages cannot be abused to bypass rate limiting.
 *
 * Helper `runWithUnlockGate(userId, fn)` does both calls for you.
 */

import { getSupabase } from "../supabase";

export class WalletLockedError extends Error {
  constructor(public retryAfterSeconds: number, public failureCount: number) {
    super(
      `Too many failed wallet unlocks. Try again in ${formatDuration(retryAfterSeconds)}.`
    );
    this.name = "WalletLockedError";
  }
}

interface LockoutStatus {
  locked: boolean;
  retry_after_seconds: number;
  failure_count: number;
}

interface LocalCounter {
  count: number;
  lockedUntil: number;
}

// In-memory fallback — used only when the DB is unreachable.
// Mirrors the server escalation schedule so DB outages don't create a bypass window.
const localCounters = new Map<string, LocalCounter>();

const LOCAL_LOCKOUT_SCHEDULE: Record<number, number> = {
  4: 30,
  5: 60,
  6: 300,
  7: 1_800,
};
function localLockoutSeconds(count: number): number {
  return LOCAL_LOCKOUT_SCHEDULE[count] ?? (count >= 8 ? 86_400 : 0);
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.ceil(seconds / 60)}m`;
  return `${Math.ceil(seconds / 3600)}h`;
}

export async function checkUnlockAllowed(userId: string): Promise<void> {
  const supabase = await getSupabase();
  const { data, error } = await supabase.rpc("check_wallet_unlock_lockout", {
    p_user_id: userId,
  });

  if (error) {
    // DB unreachable — enforce local in-memory counter so a deliberate outage
    // cannot be used to bypass the brute-force gate.
    const local = localCounters.get(userId);
    if (local && Date.now() < local.lockedUntil) {
      const remaining = Math.ceil((local.lockedUntil - Date.now()) / 1000);
      throw new WalletLockedError(remaining, local.count);
    }
    return;
  }

  const status = data as LockoutStatus | null;
  if (status?.locked) {
    throw new WalletLockedError(status.retry_after_seconds, status.failure_count);
  }
}

export async function reportUnlockAttempt(userId: string, success: boolean): Promise<void> {
  const supabase = await getSupabase();
  const { error } = await supabase.rpc("record_wallet_unlock_attempt", {
    p_user_id: userId,
    p_success: success,
  });

  if (error) {
    // DB unreachable — mirror the outcome in the local counter.
    if (success) {
      localCounters.delete(userId);
    } else {
      const local = localCounters.get(userId) ?? { count: 0, lockedUntil: 0 };
      local.count += 1;
      const lockSecs = localLockoutSeconds(local.count);
      if (lockSecs > 0) local.lockedUntil = Date.now() + lockSecs * 1_000;
      localCounters.set(userId, local);
    }
  } else if (success) {
    // Successful server report — also clear local counter.
    localCounters.delete(userId);
  }
}

/**
 * Convenience wrapper: gate-check, run the decrypt, report outcome.
 * Re-throws the underlying error so callers see the original failure reason.
 */
export async function runWithUnlockGate<T>(
  userId: string,
  fn: () => Promise<T>
): Promise<T> {
  await checkUnlockAllowed(userId);
  try {
    const result = await fn();
    // Best-effort report; never block the user from getting their result.
    void reportUnlockAttempt(userId, true).catch(() => {});
    return result;
  } catch (err) {
    void reportUnlockAttempt(userId, false).catch(() => {});
    throw err;
  }
}
