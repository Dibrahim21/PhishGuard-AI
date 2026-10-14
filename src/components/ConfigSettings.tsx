import { useState } from 'react';
import {
  User,
  ShieldCheck,
  LockKeyhole,
  Globe2,
  BadgeCheck,
  Bot,
  Database,
  Trash2,
  CheckCircle2,
  AlertTriangle,
  ChevronDown,
} from 'lucide-react';
import { SystemConfig } from '../types';
import React from 'react';
import {
  clearLocalHistory,
  loadLocalHistory,
} from '../utils/localStorage';

interface ConfigSettingsProps {
  config: SystemConfig;
  onUpdateConfig: (config: SystemConfig) => void;
  onShowToast: (message: string, isAlert?: boolean) => void;
}

export default function ConfigSettings({
  config,
  onUpdateConfig,
  onShowToast,
}: ConfigSettingsProps) {
  const [openSection, setOpenSection] = useState<string>('account');
  const [clearingHistory, setClearingHistory] = useState(false);

  const scanCount = loadLocalHistory().length;

  const toggleSection = (section: string) => {
    setOpenSection((previous) =>
      previous === section ? '' : section
    );
  };

  const handleClearHistory = () => {
    const confirmed = window.confirm(
      'Clear your entire scan history? This cannot be undone.'
    );
    if (!confirmed) return;
    setClearingHistory(true);
    try {
      clearLocalHistory();
      onShowToast('Your scan history has been cleared.');
    } catch (error: any) {
      onShowToast(error?.message || 'Unable to clear history.', true);
    } finally {
      setClearingHistory(false);
    }
  };

  const Section = ({
    id,
    title,
    icon: Icon,
    children,
  }: {
    id: string;
    title: string;
    icon: any;
    children: React.ReactNode;
  }) => {
    const isOpen = openSection === id;

    return (
      <section className="rounded-2xl border border-[#242b3b] bg-[#141b2b] overflow-hidden">
        <button
          type="button"
          onClick={() => toggleSection(id)}
          className="w-full flex items-center justify-between gap-4 px-5 py-4 hover:bg-white/[0.02] transition"
        >
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center">
              <Icon className="w-4 h-4 text-purple-400" />
            </div>

            <span className="text-sm font-bold text-white">
              {title}
            </span>
          </div>

          <ChevronDown
            className={`w-4 h-4 text-zinc-500 transition-transform ${
              isOpen ? 'rotate-180' : ''
            }`}
          />
        </button>

        {isOpen && (
          <div className="px-5 pb-5 border-t border-[#242b3b]">
            {children}
          </div>
        )}
      </section>
    );
  };

  const StatusRow = ({
    icon: Icon,
    title,
    description,
    active = true,
  }: {
    icon: any;
    title: string;
    description: string;
    active?: boolean;
  }) => (
    <div className="flex items-center justify-between gap-4 rounded-xl border border-[#252d40] bg-[#111827] p-4">
      <div className="flex items-center gap-3 min-w-0">
        <Icon className="w-4 h-4 text-teal-400 shrink-0" />
        <div className="min-w-0">
          <p className="text-sm font-semibold text-white">
            {title}
          </p>
          <p className="text-xs text-zinc-500 mt-0.5">
            {description}
          </p>
        </div>
      </div>

      <span
        className={`shrink-0 flex items-center gap-1 text-[10px] font-mono font-bold ${
          active ? 'text-teal-400' : 'text-zinc-500'
        }`}
      >
        {active ? (
          <CheckCircle2 className="w-3.5 h-3.5" />
        ) : (
          <AlertTriangle className="w-3.5 h-3.5" />
        )}
        {active ? 'ACTIVE' : 'OFF'}
      </span>
    </div>
  );

  return (
    <div className="w-full max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-4">

      {/* PAGE HEADER */}
      <div className="rounded-2xl border border-[#242b3b] bg-[#141b2b] p-5">
        <div className="flex items-center gap-3">
          <div className="w-11 h-11 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center">
            <User className="w-5 h-5 text-purple-400" />
          </div>

          <div>
            <h2 className="text-lg font-bold text-white">
              Account & System Settings
            </h2>
            <p className="text-xs text-zinc-500 mt-1">
              Manage your PhishGuard account and security configuration.
            </p>
          </div>
        </div>
      </div>

      {/* BROWSER PROFILE */}
      <Section id="account" title="Browser Profile" icon={User}>
        <div className="pt-5 space-y-3">
          <div className="rounded-xl border border-[#252d40] bg-[#111827] p-4">
            <div className="flex items-center gap-3">
              <User className="w-4 h-4 text-zinc-400" />
              <div>
                <p className="text-[10px] uppercase tracking-wider text-zinc-500">Session</p>
                <p className="text-sm text-white mt-1">Anonymous — No account required</p>
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-[#252d40] bg-[#111827] p-4">
            <div className="flex items-center gap-3">
              <Database className="w-4 h-4 text-zinc-400" />
              <div>
                <p className="text-[10px] uppercase tracking-wider text-zinc-500">Local Scan Records</p>
                <p className="text-sm text-white mt-1">{scanCount} scan{scanCount !== 1 ? 's' : ''} stored in this browser</p>
                <p className="text-[10px] text-zinc-600 mt-0.5">History is private to this browser only</p>
              </div>
            </div>
          </div>
        </div>
      </Section>

      {/* SCANNER CONFIGURATION */}
      <Section
        id="scanner"
        title="Scanner Configuration"
        icon={ShieldCheck}
      >
        <div className="pt-5 space-y-3">

          <div className="rounded-xl border border-[#252d40] bg-[#111827] p-4">
            <div className="flex items-center justify-between gap-4">
              <div>
                <p className="text-sm font-semibold text-white">
                  Risk Threshold
                </p>
                <p className="text-xs text-zinc-500 mt-1">
                  Current backend scoring thresholds.
                </p>
              </div>

              <span className="text-xs font-mono text-purple-300">
                0–34 / 35–54 / 55–100
              </span>
            </div>

            <div className="grid grid-cols-3 gap-2 mt-4">
              <div className="rounded-lg bg-teal-500/5 border border-teal-500/10 p-3 text-center">
                <p className="text-[10px] text-teal-400">LEGITIMATE</p>
                <p className="text-sm font-bold text-white mt-1">0–34</p>
              </div>

              <div className="rounded-lg bg-amber-500/5 border border-amber-500/10 p-3 text-center">
                <p className="text-[10px] text-amber-400">SUSPICIOUS</p>
                <p className="text-sm font-bold text-white mt-1">35–54</p>
              </div>

              <div className="rounded-lg bg-red-500/5 border border-red-500/10 p-3 text-center">
                <p className="text-[10px] text-red-400">PHISHING</p>
                <p className="text-sm font-bold text-white mt-1">55–100</p>
              </div>
            </div>
          </div>

          <StatusRow
            icon={LockKeyhole}
            title="SSL Analysis"
            description="Real TLS certificate and hostname checks."
          />

          <StatusRow
            icon={Globe2}
            title="Domain Intelligence"
            description="DNS, registrable-domain and trusted-domain analysis."
          />

          <StatusRow
            icon={BadgeCheck}
            title="Brand Impersonation Detection"
            description="Brand mismatch and typosquatting signals."
          />

        </div>
      </Section>

      {/* AI CONFIGURATION */}
      <Section
        id="ai"
        title="AI Configuration"
        icon={Bot}
      >
        <div className="pt-5 space-y-3">

          <StatusRow
            icon={Bot}
            title="AI Assistant"
            description="Chatbot requests are sent anonymously through the Flask backend."
          />

          <div className="rounded-xl border border-[#252d40] bg-[#111827] p-4">
            <div className="flex items-center justify-between gap-4">
              <div>
                <p className="text-sm font-semibold text-white">
                  Model Status
                </p>
                <p className="text-xs text-zinc-500 mt-1">
                  Gemini provider is configured on the backend.
                </p>
              </div>

              <span className="flex items-center gap-1.5 text-[10px] font-mono font-bold text-teal-400">
                <span className="w-2 h-2 rounded-full bg-teal-400 animate-pulse" />
                BACKEND READY
              </span>
            </div>
          </div>

        </div>
      </Section>

      {/* DATA */}
      <Section id="data" title="Data" icon={Database}>
        <div className="pt-5 space-y-3">

          <div className="rounded-xl border border-[#252d40] bg-[#111827] p-4 flex items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <Database className="w-4 h-4 text-teal-400" />
              <div>
                <p className="text-sm font-semibold text-white">
                  Scan History
                </p>
                <p className="text-xs text-zinc-500 mt-1">
                  Your scans are isolated from other user accounts.
                </p>
              </div>
            </div>

            <button
              type="button"
              onClick={() => {
                onShowToast(
                  'Open Scan History from the sidebar to view your scans.'
                );
              }}
              className="px-3 py-2 rounded-lg border border-[#30394d] text-[10px] font-mono text-zinc-300 hover:text-white hover:border-purple-500/40"
            >
              VIEW HISTORY
            </button>
          </div>

          <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 flex items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <Trash2 className="w-4 h-4 text-red-400" />
              <div>
                <p className="text-sm font-semibold text-red-300">
                  Clear My History
                </p>
                <p className="text-xs text-red-300/50 mt-1">
                  Deletes only scans belonging to this account.
                </p>
              </div>
            </div>

            <button
              type="button"
              onClick={handleClearHistory}
              disabled={clearingHistory}
              className="px-3.5 py-2 rounded-lg bg-red-500/10 border border-red-500/20 text-[10px] font-mono font-bold text-red-300 hover:bg-red-500/20 disabled:opacity-50"
            >
              {clearingHistory ? 'CLEARING...' : 'CLEAR'}
            </button>
          </div>

        </div>
      </Section>

      {/* SECURITY NOTE */}
      <div className="flex items-start gap-3 rounded-xl border border-[#242b3b] bg-[#111827] p-4">
        <LockKeyhole className="w-4 h-4 text-zinc-500 mt-0.5 shrink-0" />
        <p className="text-[11px] text-zinc-500 leading-relaxed">
          Account data and scan ownership are handled by the PhishGuard
          backend. External threat feeds and SOAR integrations are not
          presented here as connected unless they are actually implemented.
        </p>
      </div>
    </div>
  );
}

