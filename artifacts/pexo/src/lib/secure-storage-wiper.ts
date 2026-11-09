const IDB_NAME = 'pexly_storage';
const PENDING_WIPE_KEY = 'pexly_wipe_pending';
const BLOCKED_WAIT_MS = 3000;

export type IdbWipeOutcome = 'deleted' | 'cleared' | 'failed';

export interface WipeResult {
  /** True only if no wallet data can remain in the browser. */
  ok: boolean;
  indexedDb: IdbWipeOutcome;
}

/**
 * Attempts deleteDatabase and reports what really happened. A blocked delete
 * is NOT success: it means some connection (usually another tab) is still
 * holding the database open. We wait briefly (ids.ts releases connections
 * when another tab asks to delete), and if it still has not completed we
 * report 'blocked' so the caller falls back to emptying the stores.
 */
function tryDeleteDatabase(): Promise<'deleted' | 'blocked' | 'error'> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (v: 'deleted' | 'blocked' | 'error') => {
      if (settled) return;
      settled = true;
      resolve(v);
    };
    try {
      const req = indexedDB.deleteDatabase(IDB_NAME);
      req.onsuccess = () => finish('deleted');
      req.onerror = () => finish('error');
      req.onblocked = () => {
        // Give other tabs a moment to release; success can still arrive.
        setTimeout(() => finish('blocked'), BLOCKED_WAIT_MS);
      };
    } catch {
      finish('error');
    }
  });
}

async function wipeIndexedDB(): Promise<IdbWipeOutcome> {
  try {
    const { closeDBConnection, resetDBConnection } = await import('./ids');
    await closeDBConnection();
    resetDBConnection();
  } catch {
    // Continue: deletion is still attempted below.
  }

  const deletion = await tryDeleteDatabase();
  if (deletion === 'deleted') {
    try {
      const { resetDBConnection } = await import('./ids');
      resetDBConnection();
    } catch { /* non-fatal */ }
    return 'deleted';
  }

  // Blocked / errored: the database was NOT deleted. Do not report success.
  // Best available remediation is to empty every store and verify.
  try {
    const { clearAllStores, closeDBConnection } = await import('./ids');
    const emptied = await clearAllStores();
    await closeDBConnection();
    return emptied ? 'cleared' : 'failed';
  } catch {
    return 'failed';
  }
}

/**
 * Wipes all browser-side storage after logout:
 *   1. localStorage, 2. sessionStorage, 3. the IndexedDB wallet database.
 *
 * Returns what actually happened. If IndexedDB could not be deleted OR
 * verifiably emptied, ok is false and a pending-wipe marker is left behind
 * (written AFTER localStorage is cleared so it survives) so the next session
 * start completes the wipe before any wallet data is loaded.
 */
export async function wipeSecureStorage(): Promise<WipeResult> {
  try { localStorage.clear(); } catch { /* Safari private mode */ }
  try { sessionStorage.clear(); } catch { /* Safari private mode */ }

  const indexedDb = await wipeIndexedDB();
  const ok = indexedDb === 'deleted' || indexedDb === 'cleared';

  if (!ok) {
    try { localStorage.setItem(PENDING_WIPE_KEY, '1'); } catch { /* best effort */ }
  }
  return { ok, indexedDb };
}

/**
 * Call before loading any wallet data for a new session. If a previous
 * logout could not fully wipe IndexedDB, finish that job first. Returns false
 * if stale wallet data may still be present (caller must not load wallets).
 */
export async function completePendingWipeIfNeeded(): Promise<boolean> {
  let pending = false;
  try { pending = localStorage.getItem(PENDING_WIPE_KEY) === '1'; } catch { /* ignore */ }
  if (!pending) return true;

  const indexedDb = await wipeIndexedDB();
  const ok = indexedDb === 'deleted' || indexedDb === 'cleared';
  if (ok) {
    try { localStorage.removeItem(PENDING_WIPE_KEY); } catch { /* ignore */ }
  }
  return ok;
}
