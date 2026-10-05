import React, { useCallback, useEffect, useMemo, useState } from 'react';
import type { PlaybookModule } from '../types';
import { PLAYBOOK_MODULES } from '../data/mockData';

interface SocCommandCenterProps {
  onScanUrl: (url: string) => void;
  onOpenPlaybook: (module: PlaybookModule) => void;
}

interface BackendScan {
  id: number;
  url: string;
  verdict: string;
  risk_score: number;
  domain: string | null;
  scanned_at: string;
}

interface ScanHistoryRecord {
  id: string;
  url: string;
  status: 'Safe' | 'Suspicious' | 'Phishing';
  risk: number;
  time: string;
  source: string;
  createdAt: string;
}

const API_BASE = 'https://phishguard-ai-85s9.onrender.com/api';

const SocCommandCenter: React.FC<SocCommandCenterProps> = ({
  onScanUrl,
  onOpenPlaybook,
}) => {
  const [quickInputUrl, setQuickInputUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanFeedback, setScanFeedback] = useState('');

  const [scanHistory, setScanHistory] = useState<
    ScanHistoryRecord[]
  >([]);

  const [isLoadingHistory, setIsLoadingHistory] =
    useState(false);

  const [historyError, setHistoryError] =
    useState('');

  /*
   * Convert backend verdict
   */
  const mapVerdict = (
    verdict: string
  ): ScanHistoryRecord['status'] => {
    const value = String(verdict || '').toLowerCase();

    if (value === 'phishing') {
      return 'Phishing';
    }

    if (value === 'suspicious') {
      return 'Suspicious';
    }

    return 'Safe';
  };

  /*
   * Format backend timestamp
   */
  const formatTime = (raw: string) => {
    if (!raw) {
      return 'Unknown';
    }

    try {
      const normalized = raw.includes('T')
        ? raw
        : `${raw.replace(' ', 'T')}Z`;

      const date = new Date(normalized);

      if (!Number.isNaN(date.getTime())) {
        return date.toLocaleString();
      }
    } catch {
      // fallback
    }

    return raw;
  };

  /*
   * REAL DATABASE HISTORY
   *
   * Data comes from:
   * Flask -> SQLite -> /api/history
   */
  const loadScanHistory = useCallback(async () => {
    setIsLoadingHistory(true);
    setHistoryError('');

    try {
     const token =
  localStorage.getItem('phishguard_token') || '';

const response = await fetch(
  `${API_BASE}/history`,
  {
    headers: token
      ? {
          Authorization: `Bearer ${token}`,
        }
      : {},
  }
);
      if (!response.ok) {
        throw new Error(
          `History API returned HTTP ${response.status}`
        );
      }

      const data = await response.json();

      if (
        data.status !== 'success' ||
        !Array.isArray(data.scans)
      ) {
        throw new Error(
          data.message ||
            'Invalid response from history API'
        );
      }

      const mapped: ScanHistoryRecord[] =
        data.scans
          .map((scan: BackendScan) => ({
            id: `SCAN-${scan.id}`,

            url: scan.url,

            status: mapVerdict(
              scan.verdict
            ),

            risk: Math.round(
              Number(
                scan.risk_score ?? 0
              )
            ),

            time: formatTime(
              scan.scanned_at
            ),

            source:
              scan.domain ||
              'PhishGuard AI',

            createdAt:
              scan.scanned_at,
          }))
          .sort(
            (
              a: ScanHistoryRecord,
              b: ScanHistoryRecord
            ) =>
              new Date(
                b.createdAt
              ).getTime() -
              new Date(
                a.createdAt
              ).getTime()
          );

      setScanHistory(mapped);
    } catch (error) {
      console.error(
        'Dashboard history error:',
        error
      );

      setHistoryError(
        error instanceof Error
          ? error.message
          : 'Unable to load scan history.'
      );

      setScanHistory([]);
    } finally {
      setIsLoadingHistory(false);
    }
  }, []);

  /*
   * Load database history
   */
  useEffect(() => {
    void loadScanHistory();

    const handleFocus = () => {
      void loadScanHistory();
    };

    window.addEventListener(
      'focus',
      handleFocus
    );

    return () => {
      window.removeEventListener(
        'focus',
        handleFocus
      );
    };
  }, [loadScanHistory]);

  /*
   * REAL DASHBOARD METRICS
   */
  const totalScans =
    scanHistory.length;

  const safeCount =
    scanHistory.filter(
      (scan) =>
        scan.status === 'Safe'
    ).length;

  const suspiciousCount =
    scanHistory.filter(
      (scan) =>
        scan.status === 'Suspicious'
    ).length;

  const phishingCount =
    scanHistory.filter(
      (scan) =>
        scan.status === 'Phishing'
    ).length;

  const averageRisk =
    totalScans > 0
      ? Math.round(
          scanHistory.reduce(
            (sum, scan) =>
              sum + scan.risk,
            0
          ) / totalScans
        )
      : 0;

  const highestRisk =
    totalScans > 0
      ? Math.max(
          ...scanHistory.map(
            (scan) => scan.risk
          )
        )
      : 0;

  const threatRate =
    totalScans > 0
      ? Math.round(
          ((phishingCount +
            suspiciousCount) /
            totalScans) *
            100
        )
      : 0;

  const recentScans =
    useMemo(
      () =>
        scanHistory.slice(
          0,
          8
        ),
      [scanHistory]
    );

  /*
   * QUICK SCAN
   *
   * No fake setTimeout.
   * Opens actual Neural URL Scanner.
   */
  const handleQuickScan = () => {
    const url =
      quickInputUrl.trim();

    if (!url) {
      setScanFeedback(
        'Please enter a URL to scan.'
      );
      return;
    }

    setIsScanning(true);

    setScanFeedback(
      'Opening URL Scanner...'
    );

    /*
     * NeuralUrlScanner will perform
     * the actual POST /api/scan.
     */
    onScanUrl(url);

    setQuickInputUrl('');
    setIsScanning(false);
  };

  /*
   * Playbook click
   */
  const handlePlaybookClick = (
    module: PlaybookModule
  ) => {
    onOpenPlaybook(module);
  };

  return (
    <div className="min-h-full bg-[#080b12] text-white">

      {/* =========================
          HEADER
      ========================== */}

      <div className="border-b border-[#202638] bg-[#0c101a] px-6 py-5">

        <div className="flex items-center justify-between">

          <div>
            <div className="flex items-center gap-3">

              <span className="material-symbols-outlined text-[28px] text-[#4fdbc8]">
                security
              </span>

              <div>
                <h1 className="text-xl font-bold">
                  SOC Command Center
                </h1>

                <p className="mt-1 text-xs text-[#7d8597]">
                  PhishGuard AI security
                  operations dashboard
                </p>
              </div>

            </div>
          </div>

          <button
            onClick={() =>
              void loadScanHistory()
            }
            disabled={isLoadingHistory}
            className="flex items-center gap-2 rounded-lg border border-[#293044] bg-[#121826] px-4 py-2 text-xs font-semibold text-[#c7cedd] transition hover:bg-[#181f2e] disabled:opacity-50"
          >

            <span
              className={`material-symbols-outlined text-[16px] ${
                isLoadingHistory
                  ? 'animate-spin'
                  : ''
              }`}
            >
              refresh
            </span>

            Refresh
          </button>

        </div>
      </div>

      {/* =========================
          MAIN
      ========================== */}

      <main className="space-y-6 p-6">

        {/* =========================
            QUICK SCAN
        ========================== */}

        <section className="rounded-2xl border border-[#232a3a] bg-[#101521] p-5">

          <div className="mb-4">

            <h2 className="text-base font-bold">
              Quick URL Scan
            </h2>

            <p className="mt-1 text-xs text-[#7d8597]">
              Send a URL to the real
              PhishGuard detection engine.
            </p>

          </div>

          <div className="flex flex-col gap-3 md:flex-row">

            <div className="relative flex-1">

              <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-[19px] text-[#697287]">
                link
              </span>

              <input
                value={quickInputUrl}
                onChange={(e) =>
                  setQuickInputUrl(
                    e.target.value
                  )
                }
                onKeyDown={(e) => {
                  if (
                    e.key === 'Enter'
                  ) {
                    handleQuickScan();
                  }
                }}
                placeholder="https://example.com"
                className="w-full rounded-xl border border-[#293044] bg-[#0a0f18] py-3 pl-10 pr-4 text-sm text-white outline-none transition placeholder:text-[#515a6d] focus:border-[#4fdbc8]"
              />

            </div>

            <button
              onClick={handleQuickScan}
              disabled={isScanning}
              className="flex items-center justify-center gap-2 rounded-xl bg-[#4fdbc8] px-6 py-3 text-sm font-bold text-[#07100f] transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50"
            >

              <span className="material-symbols-outlined text-[19px]">
                search
              </span>

              {isScanning
                ? 'Opening...'
                : 'Scan URL'}

            </button>

          </div>

          {scanFeedback && (
            <p className="mt-3 text-xs text-[#4fdbc8]">
              {scanFeedback}
            </p>
          )}

        </section>

        {/* =========================
            METRICS
        ========================== */}

        <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-6">

          {/* Total */}

          <div className="rounded-2xl border border-[#232a3a] bg-[#101521] p-5">

            <div className="flex items-center justify-between">

              <span className="text-xs text-[#7d8597]">
                Total Scans
              </span>

              <span className="material-symbols-outlined text-[20px] text-[#8b7cff]">
                analytics
              </span>

            </div>

            <p className="mt-3 text-2xl font-bold">
              {totalScans}
            </p>

            <p className="mt-1 text-[10px] text-[#596174]">
              Persisted database records
            </p>

          </div>

          {/* Safe */}

          <div className="rounded-2xl border border-[#232a3a] bg-[#101521] p-5">

            <div className="flex items-center justify-between">

              <span className="text-xs text-[#7d8597]">
                Safe
              </span>

              <span className="material-symbols-outlined text-[20px] text-[#4fdbc8]">
                verified
              </span>

            </div>

            <p className="mt-3 text-2xl font-bold text-[#4fdbc8]">
              {safeCount}
            </p>

          </div>

          {/* Suspicious */}

          <div className="rounded-2xl border border-[#232a3a] bg-[#101521] p-5">

            <div className="flex items-center justify-between">

              <span className="text-xs text-[#7d8597]">
                Suspicious
              </span>

              <span className="material-symbols-outlined text-[20px] text-[#f59e0b]">
                warning
              </span>

            </div>

            <p className="mt-3 text-2xl font-bold text-[#f59e0b]">
              {suspiciousCount}
            </p>

          </div>

          {/* Phishing */}

          <div className="rounded-2xl border border-[#232a3a] bg-[#101521] p-5">

            <div className="flex items-center justify-between">

              <span className="text-xs text-[#7d8597]">
                Phishing
              </span>

              <span className="material-symbols-outlined text-[20px] text-[#ff5451]">
                  warning
              </span>

            </div>

            <p className="mt-3 text-2xl font-bold text-[#ff5451]">
              {phishingCount}
            </p>

          </div>

          {/* Average */}

          <div className="rounded-2xl border border-[#232a3a] bg-[#101521] p-5">

            <div className="flex items-center justify-between">

              <span className="text-xs text-[#7d8597]">
                Avg Risk
              </span>

              <span className="material-symbols-outlined text-[20px] text-[#c084fc]">
                speed
              </span>

            </div>

            <p className="mt-3 text-2xl font-bold">
              {averageRisk}
              <span className="ml-1 text-sm text-[#596174]">
                /100
              </span>
            </p>

          </div>

          {/* Threat rate */}

          <div className="rounded-2xl border border-[#232a3a] bg-[#101521] p-5">

            <div className="flex items-center justify-between">

              <span className="text-xs text-[#7d8597]">
                Threat Rate
              </span>

              <span className="material-symbols-outlined text-[20px] text-[#ff5451]">
                trending_up
              </span>

            </div>

            <p className="mt-3 text-2xl font-bold">
              {threatRate}%
            </p>

            <p className="mt-1 text-[10px] text-[#596174]">
              Suspicious + phishing
            </p>

          </div>

        </section>

        {/* =========================
            ANALYTICS
        ========================== */}

        <section className="grid grid-cols-1 gap-6 lg:grid-cols-3">

          <div className="rounded-2xl border border-[#232a3a] bg-[#101521] p-5 lg:col-span-2">

            <div className="flex items-center justify-between">

              <div>
                <h2 className="text-base font-bold">
                  Risk Analytics
                </h2>

                <p className="mt-1 text-xs text-[#7d8597]">
                  Analytics generated from
                  persisted URL scan telemetry.
                </p>
              </div>

              <span className="rounded-full border border-[#293044] bg-[#0a0f18] px-3 py-1 text-[10px] font-semibold text-[#7d8597]">
                SQLITE
              </span>

            </div>

            <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-3">

              <div className="rounded-xl border border-[#232a3a] bg-[#0b101a] p-4">

                <p className="text-[10px] uppercase tracking-wider text-[#697287]">
                  Highest Risk
                </p>

                <p className="mt-2 text-2xl font-bold text-[#ff5451]">
                  {highestRisk}
                </p>

              </div>

              <div className="rounded-xl border border-[#232a3a] bg-[#0b101a] p-4">

                <p className="text-[10px] uppercase tracking-wider text-[#697287]">
                  Threat Records
                </p>

                <p className="mt-2 text-2xl font-bold">
                  {phishingCount +
                    suspiciousCount}
                </p>

              </div>

              <div className="rounded-xl border border-[#232a3a] bg-[#0b101a] p-4">

                <p className="text-[10px] uppercase tracking-wider text-[#697287]">
                  Database Status
                </p>

                <div className="mt-2 flex items-center gap-2">

                  <span className="h-2 w-2 rounded-full bg-[#4fdbc8]" />

                  <span className="text-sm font-semibold text-[#4fdbc8]">
                    Connected
                  </span>

                </div>

              </div>

            </div>

          </div>

          {/* System status */}

          <div className="rounded-2xl border border-[#232a3a] bg-[#101521] p-5">

            <h2 className="text-base font-bold">
              Detection Pipeline
            </h2>

            <p className="mt-1 text-xs text-[#7d8597]">
              Current backend components
            </p>

            <div className="mt-5 space-y-3">

              {[
                'ML Phishing Model',
                'Domain Intelligence',
                'Risk Engine',
                'SSL Analyzer',
                'SQLite Scan History',
              ].map((item) => (
                <div
                  key={item}
                  className="flex items-center justify-between rounded-lg border border-[#232a3a] bg-[#0b101a] px-3 py-3"
                >

                  <span className="text-xs text-[#c7cedd]">
                    {item}
                  </span>

                  <span className="flex items-center gap-2 text-[10px] font-bold uppercase text-[#4fdbc8]">

                    <span className="h-1.5 w-1.5 rounded-full bg-[#4fdbc8]" />

                    Active

                  </span>

                </div>
              ))}

            </div>

          </div>

        </section>

        {/* =========================
            RECENT SCANS
        ========================== */}

        <section className="rounded-2xl border border-[#232a3a] bg-[#101521]">

          <div className="flex items-center justify-between border-b border-[#232a3a] px-5 py-4">

            <div>

              <h2 className="text-base font-bold">
                Recent Scan Activity
              </h2>

              <p className="mt-1 text-xs text-[#7d8597]">
                Latest records from SQLite
                scan history.
              </p>

            </div>

            <button
              onClick={() =>
                void loadScanHistory()
              }
              className="text-xs font-semibold text-[#4fdbc8] hover:underline"
            >
              Refresh
            </button>

          </div>

          {historyError ? (

            <div className="px-5 py-12 text-center">

              <span className="material-symbols-outlined text-[38px] text-[#ff5451]">
                cloud_off
              </span>

              <p className="mt-3 text-sm font-semibold">
                Unable to load database telemetry
              </p>

              <p className="mt-1 text-xs text-[#7d8597]">
                {historyError}
              </p>

              <button
                onClick={() =>
                  void loadScanHistory()
                }
                className="mt-4 rounded-lg border border-[#293044] bg-[#171d2a] px-4 py-2 text-xs font-semibold"
              >
                Retry
              </button>

            </div>

          ) : isLoadingHistory ? (

            <div className="flex items-center justify-center py-16">

              <span className="material-symbols-outlined animate-spin text-[30px] text-[#4fdbc8]">
                progress_activity
              </span>

            </div>

          ) : recentScans.length === 0 ? (

            <div className="px-5 py-16 text-center">

              <span className="material-symbols-outlined text-[40px] text-[#495064]">
                history
              </span>

              <p className="mt-3 text-sm font-semibold">
                No scans yet
              </p>

              <p className="mt-1 text-xs text-[#7d8597]">
                Scan a URL to create your
                first database record.
              </p>

            </div>

          ) : (

            <div className="divide-y divide-[#232a3a]">

              {recentScans.map(
                (scan) => {

                  const statusColor =
                    scan.status ===
                    'Phishing'
                      ? 'text-[#ff5451]'
                      : scan.status ===
                        'Suspicious'
                        ? 'text-[#f59e0b]'
                        : 'text-[#4fdbc8]';

                  const statusIcon =
                    scan.status ===
                    'Phishing'
                      ? 'dangerous'
                      : scan.status ===
                        'Suspicious'
                        ? 'warning'
                        : 'verified';

                  return (
                    <div
                      key={scan.id}
                      className="flex flex-col gap-3 px-5 py-4 transition hover:bg-[#0c111c] md:flex-row md:items-center md:justify-between"
                    >

                      <div className="min-w-0">

                        <div className="flex items-center gap-2">

                          <span
                            className={`material-symbols-outlined text-[18px] ${statusColor}`}
                          >
                            {statusIcon}
                          </span>

                          <span className="truncate text-sm font-semibold text-white">
                            {scan.url}
                          </span>

                        </div>

                        <div className="mt-1 flex flex-wrap gap-3 text-[10px] text-[#697287]">

                          <span>
                            {scan.id}
                          </span>

                          <span>
                            {scan.source}
                          </span>

                          <span>
                            {scan.time}
                          </span>

                        </div>

                      </div>

                      <div className="flex items-center gap-5">

                        <div className="text-right">

                          <p className="text-[10px] uppercase tracking-wider text-[#596174]">
                            Risk
                          </p>

                          <p
                            className={`text-sm font-bold ${statusColor}`}
                          >
                            {scan.risk}/100
                          </p>

                        </div>

                        <span
                          className={`rounded-full border px-3 py-1 text-[10px] font-bold uppercase ${statusColor}`}
                        >
                          {scan.status}
                        </span>

                      </div>

                    </div>
                  );
                }
              )}

            </div>

          )}

        </section>

        {/* =========================
            SECURITY PLAYBOOKS
        ========================== */}

        <section>

          <div className="mb-4">

            <h2 className="text-base font-bold">
              Security Playbooks
            </h2>

            <p className="mt-1 text-xs text-[#7d8597]">
              Incident response and security
              investigation modules.
            </p>

          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">

            {PLAYBOOK_MODULES.map(
              (module) => (

                <button
                  key={module.id}
                  onClick={() =>
                    handlePlaybookClick(
                      module
                    )
                  }
                  className="group rounded-2xl border border-[#232a3a] bg-[#101521] p-5 text-left transition hover:border-[#3a455e] hover:bg-[#131a27]"
                >

                  <div className="flex items-start justify-between">

                    <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#191f2f]">

                      <span className="material-symbols-outlined text-[21px] text-[#4fdbc8]">
                        security
                      </span>

                    </div>

                    <span className="material-symbols-outlined text-[18px] text-[#4b5468] transition group-hover:text-[#4fdbc8]">
                      arrow_forward
                    </span>

                  </div>

                  <h3 className="mt-4 text-sm font-bold">
                    {module.title}
                  </h3>

                  <p className="mt-2 line-clamp-3 text-xs leading-5 text-[#7d8597]">
                    {module.description}
                  </p>

                </button>

              )
            )}

          </div>

        </section>

      </main>

    </div>
  );
};

export default SocCommandCenter;
