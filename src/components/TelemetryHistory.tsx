import { useEffect, useMemo, useState, useCallback } from 'react';

interface TelemetryHistoryProps {
  onInspectUrl: (url: string) => void;
  onShowToast: (message: string, isAlert?: boolean) => void;
}

type ScanRecord = {
  id: string;
  numericId: number;
  url: string;
  status: 'Phishing' | 'Suspicious' | 'Safe';
  risk: number;
  time: string;
  source: string;
  createdAt: string;
};

interface BackendScan {
  id: number;
  url: string;
  verdict: string;
  risk_score: number;
  phishing_probability: number | null;
  legitimate_probability: number | null;
  domain: string | null;
  scanned_at: string;
}

const API_BASE = 'https://phishguard-ai-85s9.onrender.com/api/history';

const getAuthHeaders = (): Record<string, string> => {
  const token = localStorage.getItem('phishguard_token') || '';

  return token
    ? { Authorization: `Bearer ${token}` }
    : {};
};

export default function TelemetryHistory({
  onInspectUrl,
  onShowToast,
}: TelemetryHistoryProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [filter, setFilter] = useState<'All' | 'Phishing' | 'Suspicious' | 'Safe'>('All');
  const [records, setRecords] = useState<ScanRecord[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isDeleting, setIsDeleting] = useState<boolean>(false);

  const formatTimestamp = (raw: string): string => {
    if (!raw) return 'Unknown';
    try {
      const isoString = raw.includes('T') ? raw : raw.replace(' ', 'T') + 'Z';
      const parsed = new Date(isoString);
      if (!isNaN(parsed.getTime())) {
        return parsed.toLocaleString();
      }
    } catch {
      // fallback to raw
    }
    return raw;
  };

  const mapVerdictToStatus = (verdict: string): 'Phishing' | 'Suspicious' | 'Safe' => {
    const v = (verdict || '').toLowerCase();
    if (v === 'phishing') return 'Phishing';
    if (v === 'suspicious') return 'Suspicious';
    return 'Safe';
  };

  const fetchHistory = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage(null);

    try {
      const response = await fetch(API_BASE, {
        headers: getAuthHeaders(),
      });

      if (!response.ok) {
        throw new Error(`Failed to load history (HTTP ${response.status})`);
      }

      const data = await response.json();

      if (data.status === 'success' && Array.isArray(data.scans)) {
        const mappedRecords: ScanRecord[] = data.scans.map((scan: BackendScan) => ({
          id: `SCAN-${scan.id}`,
          numericId: scan.id,
          url: scan.url,
          status: mapVerdictToStatus(scan.verdict),
          risk: Math.round(Number(scan.risk_score || 0)),
          time: formatTimestamp(scan.scanned_at),
          source: scan.domain || 'PhishGuard AI',
          createdAt: scan.scanned_at,
        }));
        setRecords(mappedRecords);
      } else {
        throw new Error(data.message || 'Invalid response from history API');
      }
    } catch (err: any) {
      console.error('Error fetching scan history:', err);
      setErrorMessage(err.message || 'Backend is unavailable');
      setRecords([]);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  const filteredRecords = useMemo(() => {
    return records.filter((record) => {
      const matchesSearch =
        record.url.toLowerCase().includes(searchQuery.toLowerCase()) ||
        record.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        String(record.numericId).includes(searchQuery.trim());

      const matchesFilter =
        filter === 'All' || record.status === filter;

      return matchesSearch && matchesFilter;
    });
  }, [records, searchQuery, filter]);

  const phishingCount = records.filter(
    (record) => record.status === 'Phishing'
  ).length;

  const suspiciousCount = records.filter(
    (record) => record.status === 'Suspicious'
  ).length;

  const safeCount = records.filter(
    (record) => record.status === 'Safe'
  ).length;

  const clearHistory = async () => {
    setIsDeleting(true);
    try {
      const response = await fetch(API_BASE, {
        method: 'DELETE',
        headers: getAuthHeaders(),
      });

      if (!response.ok) {
        throw new Error('Failed to clear history on backend');
      }

      setRecords([]);
      onShowToast('Scan history cleared successfully');
    } catch (err: any) {
      onShowToast(err.message || 'Failed to clear scan history', true);
    } finally {
      setIsDeleting(false);
    }
  };

  const deleteSingleRecord = async (scanId: number) => {
    try {
      const response = await fetch(`${API_BASE}/${scanId}`, {
        method: 'DELETE',
        headers: getAuthHeaders(),
      });

      if (!response.ok) {
        throw new Error(`Failed to delete scan #${scanId}`);
      }

      setRecords((prev) => prev.filter((r) => r.numericId !== scanId));
      onShowToast(`Scan #${scanId} deleted successfully`);
    } catch (err: any) {
      onShowToast(err.message || 'Failed to delete scan record', true);
    }
  };

  const getStatusStyle = (status: ScanRecord['status']) => {
    if (status === 'Phishing') {
      return 'bg-red-500/10 text-red-400 border-red-500/20';
    }

    if (status === 'Suspicious') {
      return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
    }

    return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
  };

  const getRiskColor = (risk: number) => {
    if (risk >= 80) {
      return 'bg-red-500';
    }

    if (risk >= 50) {
      return 'bg-yellow-400';
    }

    return 'bg-emerald-400';
  };

  return (
    <div className="w-full text-[#dce2f7]">

      {/* Page Header */}
      <div className="flex flex-col gap-4 mb-6 lg:flex-row lg:items-center lg:justify-between">

        <div>
          <div className="flex items-center gap-3">

            <h1 className="text-2xl font-bold">
              Scan History
            </h1>

            <span className="px-2 py-1 text-[10px] font-bold tracking-wider text-teal-300 uppercase border rounded-full bg-teal-500/10 border-teal-500/20">
              Active
            </span>

          </div>

          <p className="mt-1 text-sm text-[#8f96a8]">
            Forensic audit logs and previously analyzed threat records from SQLite database
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchHistory}
            disabled={isLoading}
            className="flex items-center justify-center gap-2 px-3 py-2.5 text-xs font-semibold text-purple-300 transition-colors border rounded-lg bg-purple-500/10 border-purple-500/20 hover:bg-purple-500/20 disabled:opacity-40"
            title="Reload from backend"
          >
            <span className={`material-symbols-outlined text-[18px] ${isLoading ? 'animate-spin' : ''}`}>
              refresh
            </span>
            Refresh
          </button>

          <button
            onClick={clearHistory}
            disabled={records.length === 0 || isDeleting}
            className="flex items-center justify-center gap-2 px-4 py-2.5 text-xs font-semibold text-red-300 transition-colors border rounded-lg bg-red-500/10 border-red-500/20 hover:bg-red-500/20 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <span className="material-symbols-outlined text-[18px]">
              delete
            </span>
            Clear History
          </button>
        </div>

      </div>

      {/* Statistics */}
      <div className="grid grid-cols-1 gap-4 mb-6 sm:grid-cols-2 xl:grid-cols-4">

        <div className="p-4 border rounded-xl bg-[#141b2b] border-[#232a3a]">

          <div className="flex items-center justify-between">

            <span className="text-xs text-[#8f96a8]">
              Total Scans
            </span>

            <span className="material-symbols-outlined text-purple-300">
              history
            </span>

          </div>

          <p className="mt-3 text-2xl font-bold">
            {records.length}
          </p>

          <p className="mt-1 text-[11px] text-[#8f96a8]">
            Recorded security analyses
          </p>

        </div>

        <div className="p-4 border rounded-xl bg-[#141b2b] border-[#232a3a]">

          <div className="flex items-center justify-between">

            <span className="text-xs text-[#8f96a8]">
              Phishing
            </span>

            <span className="material-symbols-outlined text-red-400">
              warning
            </span>

          </div>

          <p className="mt-3 text-2xl font-bold text-red-400">
            {phishingCount}
          </p>

          <p className="mt-1 text-[11px] text-[#8f96a8]">
            High-risk detections
          </p>

        </div>

        <div className="p-4 border rounded-xl bg-[#141b2b] border-[#232a3a]">

          <div className="flex items-center justify-between">

            <span className="text-xs text-[#8f96a8]">
              Suspicious
            </span>

            <span className="material-symbols-outlined text-yellow-400">
              visibility
            </span>

          </div>

          <p className="mt-3 text-2xl font-bold text-yellow-400">
            {suspiciousCount}
          </p>

          <p className="mt-1 text-[11px] text-[#8f96a8]">
            Requires further review
          </p>

        </div>

        <div className="p-4 border rounded-xl bg-[#141b2b] border-[#232a3a]">

          <div className="flex items-center justify-between">

            <span className="text-xs text-[#8f96a8]">
              Safe
            </span>

            <span className="material-symbols-outlined text-emerald-400">
              verified
            </span>

          </div>

          <p className="mt-3 text-2xl font-bold text-emerald-400">
            {safeCount}
          </p>

          <p className="mt-1 text-[11px] text-[#8f96a8]">
            Low-risk URLs
          </p>

        </div>

      </div>

      {/* Search and Filter */}
      <div className="flex flex-col gap-3 p-4 mb-5 border rounded-xl bg-[#141b2b] border-[#232a3a] md:flex-row">

        <div className="relative flex-1">

          <span className="absolute material-symbols-outlined left-3 top-3 text-[#7d8597] text-[18px]">
            search
          </span>

          <input
            type="text"
            value={searchQuery}
            onChange={(event) =>
              setSearchQuery(event.target.value)
            }
            placeholder="Search domain or scan ID..."
            className="w-full h-11 pl-10 pr-4 text-sm border rounded-lg outline-none bg-[#0b101c] border-[#232a3a] text-[#dce2f7] placeholder:text-[#687083] focus:border-purple-500"
          />

        </div>

        <div className="flex gap-2 overflow-x-auto">

          {(
            [
              'All',
              'Phishing',
              'Suspicious',
              'Safe',
            ] as const
          ).map((item) => (

            <button
              key={item}
              onClick={() =>
                setFilter(item)
              }
              className={`px-4 py-2 rounded-lg text-xs font-semibold whitespace-nowrap transition-all ${
                filter === item
                  ? 'bg-purple-600 text-white'
                  : 'bg-[#0b101c] border border-[#232a3a] text-[#9fa7b8] hover:text-white'
              }`}
            >
              {item}
            </button>

          ))}

        </div>

      </div>

      {/* History Table Container */}
      <div className="overflow-hidden border rounded-xl bg-[#141b2b] border-[#232a3a]">

        <div className="flex items-center justify-between p-4 border-b border-[#232a3a]">

          <div>

            <h2 className="font-semibold">
              Security Telemetry
            </h2>

            <p className="mt-1 text-xs text-[#7d8597]">
              {filteredRecords.length} records found
            </p>

          </div>

          <span className="flex items-center gap-2 text-xs text-teal-400">

            <span className="w-2 h-2 bg-teal-400 rounded-full animate-pulse" />

            DATABASE AUDIT LOG

          </span>

        </div>

        {/* State: Loading */}
        {isLoading ? (

          <div className="flex flex-col items-center justify-center py-20 text-[#8f96a8]">

            <span className="mb-3 material-symbols-outlined text-[42px] animate-spin text-purple-400">
              progress_activity
            </span>

            <h3 className="text-base font-semibold text-[#dce2f7]">
              Loading scan history...
            </h3>

            <p className="mt-1 text-sm text-[#7d8597]">
              Fetching real scan records from backend database
            </p>

          </div>

        ) : errorMessage ? (

          /* State: Error */
          <div className="flex flex-col items-center justify-center py-20 text-red-400">

            <span className="mb-3 material-symbols-outlined text-[42px]">
              cloud_off
            </span>

            <h3 className="text-base font-semibold">
              Backend is unavailable
            </h3>

            <p className="mt-1 text-sm text-[#8f96a8]">
              {errorMessage}
            </p>

            <button
              onClick={fetchHistory}
              className="inline-flex items-center gap-2 px-4 py-2 mt-4 text-xs font-semibold text-purple-300 transition-colors border rounded-lg bg-purple-500/10 border-purple-500/20 hover:bg-purple-500/20"
            >
              <span className="material-symbols-outlined text-[16px]">
                refresh
              </span>
              Retry
            </button>

          </div>

        ) : records.length === 0 ? (

          /* State: Empty records */
          <div className="flex flex-col items-center justify-center py-20">

            <span className="mb-3 material-symbols-outlined text-[42px] text-[#495064]">
              history
            </span>

            <h3 className="text-base font-semibold">
              No scans found.
            </h3>

            <p className="mt-1 text-sm text-[#7d8597]">
              Scan URLs to create security telemetry records.
            </p>

          </div>

        ) : filteredRecords.length === 0 ? (

          /* State: No matching filter */
          <div className="flex flex-col items-center justify-center py-20">

            <span className="mb-3 material-symbols-outlined text-[42px] text-[#495064]">
              search_off
            </span>

            <h3 className="text-base font-semibold">
              No matching scans found.
            </h3>

            <p className="mt-1 text-sm text-[#7d8597]">
              Try adjusting your search query or filter.
            </p>

          </div>

        ) : (

          /* State: Table with records */
          <div className="overflow-x-auto">

            <table className="w-full min-w-[760px]">

              <thead>

                <tr className="border-b bg-[#0b101c] border-[#232a3a]">

                  <th className="px-5 py-4 text-[10px] tracking-wider text-left uppercase text-[#7d8597]">
                    Scan ID
                  </th>

                  <th className="px-5 py-4 text-[10px] tracking-wider text-left uppercase text-[#7d8597]">
                    Target URL
                  </th>

                  <th className="px-5 py-4 text-[10px] tracking-wider text-left uppercase text-[#7d8597]">
                    Verdict
                  </th>

                  <th className="px-5 py-4 text-[10px] tracking-wider text-left uppercase text-[#7d8597]">
                    Risk Score
                  </th>

                  <th className="px-5 py-4 text-[10px] tracking-wider text-left uppercase text-[#7d8597]">
                    Time
                  </th>

                  <th className="px-5 py-4 text-[10px] tracking-wider text-right uppercase text-[#7d8597]">
                    Action
                  </th>

                </tr>

              </thead>

              <tbody>

                {filteredRecords.map((record) => (

                  <tr
                    key={record.numericId}
                    className="border-b border-[#232a3a] last:border-b-0 hover:bg-[#191f2f]/50 transition-colors"
                  >

                    <td className="px-5 py-4">

                      <span className="font-mono text-xs text-purple-300">
                        {record.id}
                      </span>

                    </td>

                    <td className="px-5 py-4">

                      <div className="max-w-[280px] truncate text-sm text-[#dce2f7]" title={record.url}>
                        {record.url}
                      </div>

                      <span className="text-[10px] text-[#687083]">
                        {record.source}
                      </span>

                    </td>

                    <td className="px-5 py-4">

                      <span
                        className={`inline-flex px-2.5 py-1 rounded-full text-[10px] font-bold border ${getStatusStyle(
                          record.status
                        )}`}
                      >
                        {record.status}
                      </span>

                    </td>

                    <td className="px-5 py-4">

                      <div className="flex items-center gap-2">

                        <div className="w-20 h-1.5 overflow-hidden rounded-full bg-[#0b101c]">

                          <div
                            className={`h-full rounded-full ${getRiskColor(
                              record.risk
                            )}`}
                            style={{
                              width: `${record.risk}%`,
                            }}
                          />

                        </div>

                        <span className="text-xs font-bold">
                          {record.risk}%
                        </span>

                      </div>

                    </td>

                    <td className="px-5 py-4 text-xs text-[#8f96a8]">
                      {record.time}
                    </td>

                    <td className="px-5 py-4 text-right">

                      <div className="inline-flex items-center justify-end gap-2">

                        <button
                          onClick={() => {
                            onInspectUrl(record.url);

                            onShowToast(
                              `Opening ${record.id} for detailed inspection`
                            );
                          }}
                          className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-purple-300 transition-colors border rounded-lg bg-purple-500/10 border-purple-500/20 hover:bg-purple-500/20"
                        >

                          <span className="material-symbols-outlined text-[16px]">
                            visibility
                          </span>

                          Inspect

                        </button>

                        <button
                          onClick={() => deleteSingleRecord(record.numericId)}
                          title={`Delete ${record.id}`}
                          className="inline-flex items-center justify-center p-2 text-xs font-semibold text-red-300 transition-colors border rounded-lg bg-red-500/10 border-red-500/20 hover:bg-red-500/20"
                        >

                          <span className="material-symbols-outlined text-[16px]">
                            delete
                          </span>

                        </button>

                      </div>

                    </td>

                  </tr>

                ))}

              </tbody>

            </table>

          </div>

        )}

      </div>

    </div>
  );
}
