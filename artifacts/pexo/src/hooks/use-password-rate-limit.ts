import { useState, useEffect, useCallback, useRef } from "react";

/**
 * Client-side brute-force guard for password-gated operations.
 *
 * Tracks wrong-password attempts in memory (resets on page reload — intentional,
 * this is a UX first-layer guard, not a hard security control).  The server-side
 * wallet-unlock-gate provides the durable limit (up to 24 h lockout).
 *
 * Lockout schedule (defaults):
 *   attempts 1–4     → allowed
 *   attempt  5       → 10 s lockout     (baseDelayMs × 3^0)
 *   attempt 10       → 30 s lockout     (baseDelayMs × 3^1)
 *   attempt 15       → 90 s lockout     (baseDelayMs × 3^2)
 *   attempt 20       → 270 s lockout    (baseDelayMs × 3^3)
 *   attempt 25+      → 300 s lockout    (capped at maxDelayMs)
 */
export interface PasswordRateLimitOptions {
  maxAttempts?: number;
  baseDelayMs?: number;
  multiplier?:  number;
  maxDelayMs?:  number;
}

export interface PasswordRateLimitState {
  isLocked:       boolean;
  lockoutSeconds: number;
  attempts:       number;
  recordFailure:  () => void;
  reset:          () => void;
}

export function usePasswordRateLimit(
  opts?: PasswordRateLimitOptions
): PasswordRateLimitState {
  const maxAttempts = opts?.maxAttempts ?? 5;
  const baseDelayMs = opts?.baseDelayMs ?? 10_000;
  const multiplier  = opts?.multiplier  ?? 3;
  const maxDelayMs  = opts?.maxDelayMs  ?? 300_000;

  const failureCount  = useRef(0);
  const lockoutCount  = useRef(0);

  const [lockoutUntil,   setLockoutUntil]   = useState<number>(0);
  const [lockoutSeconds, setLockoutSeconds] = useState<number>(0);

  useEffect(() => {
    if (lockoutUntil <= Date.now()) {
      setLockoutSeconds(0);
      return;
    }
    const tick = setInterval(() => {
      const remaining = Math.ceil((lockoutUntil - Date.now()) / 1000);
      if (remaining <= 0) {
        setLockoutSeconds(0);
        clearInterval(tick);
      } else {
        setLockoutSeconds(remaining);
      }
    }, 500);
    return () => clearInterval(tick);
  }, [lockoutUntil]);

  const recordFailure = useCallback(() => {
    failureCount.current += 1;
    if (failureCount.current >= maxAttempts) {
      const delay = Math.min(
        baseDelayMs * Math.pow(multiplier, lockoutCount.current),
        maxDelayMs
      );
      lockoutCount.current += 1;
      failureCount.current = 0;
      const until = Date.now() + delay;
      setLockoutUntil(until);
      setLockoutSeconds(Math.ceil(delay / 1000));
    }
  }, [maxAttempts, baseDelayMs, multiplier, maxDelayMs]);

  const reset = useCallback(() => {
    failureCount.current = 0;
    lockoutCount.current = 0;
    setLockoutUntil(0);
    setLockoutSeconds(0);
  }, []);

  return {
    isLocked:       lockoutSeconds > 0,
    lockoutSeconds,
    attempts:       failureCount.current,
    recordFailure,
    reset,
  };
}
