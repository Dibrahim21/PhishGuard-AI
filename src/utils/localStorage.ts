/**
 * PhishGuard AI – Browser-Local Scan History
 *
 * All scan history is stored exclusively in this browser's localStorage.
 * No data is shared across browsers or sessions, and no backend history
 * endpoints are called by the anonymous frontend.
 */

export const SCAN_HISTORY_KEY = 'phishguard_scan_history';

export interface LocalScanRecord {
  /** Auto-generated UUID for this browser record */
  localId: string;
  /** Human-readable label e.g. "SCAN-1" */
  id: string;
  url: string;
  verdict: string;
  /** 0-100 */
  risk_score: number;
  phishing_probability: number;
  legitimate_probability: number;
  domain: string;
  /** ISO-8601 timestamp */
  scanned_at: string;
}

/** Load all scan records from localStorage, newest-first. */
export function loadLocalHistory(): LocalScanRecord[] {
  try {
    const raw = localStorage.getItem(SCAN_HISTORY_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    // Filter out any malformed entries
    return parsed.filter(
      (r) =>
        r &&
        typeof r === 'object' &&
        typeof r.localId === 'string' &&
        typeof r.url === 'string'
    );
  } catch {
    return [];
  }
}

/** Persist the full list back to localStorage. */
function saveAll(records: LocalScanRecord[]): void {
  try {
    localStorage.setItem(SCAN_HISTORY_KEY, JSON.stringify(records));
  } catch {
    // Storage quota exceeded or private browsing restriction — silently ignore.
  }
}

/** Append a new scan record to localStorage history. */
export function saveToLocalHistory(
  record: Omit<LocalScanRecord, 'localId' | 'id'>
): LocalScanRecord {
  const existing = loadLocalHistory();
  const nextIndex = existing.length + 1;

  const newRecord: LocalScanRecord = {
    localId: `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
    id: `SCAN-${nextIndex}`,
    ...record,
  };

  // Prepend so newest appears first; cap at 500 records to avoid quota issues.
  const updated = [newRecord, ...existing].slice(0, 500);
  saveAll(updated);
  return newRecord;
}

/** Remove a single record by localId. */
export function deleteFromLocalHistory(localId: string): void {
  const existing = loadLocalHistory();
  saveAll(existing.filter((r) => r.localId !== localId));
}

/** Wipe all scan history from localStorage. */
export function clearLocalHistory(): void {
  try {
    localStorage.removeItem(SCAN_HISTORY_KEY);
  } catch {
    // Ignore.
  }
}
