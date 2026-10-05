import { useEffect, useState } from 'react';
import { Shield, Radar, History, Bot, Lightbulb, Settings, Sparkles, Activity, ChevronRight, X } from 'lucide-react';
import { NavTab } from '../types';

interface SidebarProps {
  currentTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  radarActive: boolean;
  mobileOpen: boolean;
  onCloseMobile: () => void;
}

export default function Sidebar({
  currentTab,
  onTabChange,
  radarActive,
  mobileOpen,
  onCloseMobile,
}: SidebarProps) {
  // Normalize current tab
  const isDashboard = currentTab === 'dashboard' || currentTab === 'soc';
  const isScanner = currentTab === 'scanner' || currentTab === 'scan';
  const isHistory = currentTab === 'history' || currentTab === 'logs';
  const isChatbot = currentTab === 'chatbot' || currentTab === 'sentinel';
  const isTips = currentTab === 'tips';
  const isSettings = currentTab === 'settings' || currentTab === 'config';

  const [scanCount, setScanCount] = useState(0);
  const [backendOnline, setBackendOnline] = useState(false);

  useEffect(() => {
    const checkBackend = async () => {
      try {
        const token =
  localStorage.getItem('phishguard_token') || '';

const response = await fetch(
  'https://phishguard-ai-85s9.onrender.com/api/history',
  {
    headers: token
      ? {
          Authorization: `Bearer ${token}`,
        }
      : {},
  }
);
        const data = await response.json();

        setBackendOnline(
          response.ok && data?.status === 'success'
        );
      } catch (error) {
        console.error('Backend health check failed:', error);
        setBackendOnline(false);
      }
    };

    checkBackend();

    const interval = window.setInterval(checkBackend, 30000);
    return () => window.clearInterval(interval);
  }, []);


  useEffect(() => {
    const fetchScanCount = async () => {
      try {
        const response = await fetch('https://phishguard-ai-85s9.onrender.com/api/history');

        if (!response.ok) {
          throw new Error(`History API returned HTTP ${response.status}`);
        }

        const data = await response.json();

        if (data.status === 'success' && Array.isArray(data.scans)) {
          setScanCount(data.scans.length);
        }
      } catch (error) {
        console.error('Failed to load scan count:', error);
      }
    };

    fetchScanCount();
  }, []);

  const navItems = [
    {
      id: 'dashboard' as NavTab,
      label: 'Dashboard',
      icon: Shield,
      active: isDashboard,
      badge: null,
      description: 'SOC overview & telemetry',
    },
    {
      id: 'scanner' as NavTab,
      label: 'URL Scanner',
      icon: Radar,
      active: isScanner,
      badge: 'Live',
      badgeClass: 'bg-teal-500/15 text-teal-400 border border-teal-500/30',
      description: 'Neural deep inspection',
    },
    {
      id: 'history' as NavTab,
      label: 'Scan History',
      icon: History,
      active: isHistory,
      badge: String(scanCount),
      badgeClass: 'bg-zinc-800 text-zinc-400',
      description: 'Forensics & audit logs',
    },
    {
      id: 'chatbot' as NavTab,
      label: 'AI Security Chatbot',
      icon: Bot,
      active: isChatbot,
      badge: 'AI',
      badgeClass: 'bg-purple-500/20 text-purple-300 border border-purple-500/40',
      description: 'Sentinel threat advisor',
    },
    {
      id: 'tips' as NavTab,
      label: 'Security Tips',
      icon: Lightbulb,
      active: isTips,
      badge: 'Tips',
      badgeClass: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30',
      description: 'Tactics & playbooks',
    },
    {
      id: 'settings' as NavTab,
      label: 'Settings',
      icon: Settings,
      active: isSettings,
      badge: null,
      description: 'Heuristics & webhooks',
    },
  ];

  const handleSelectTab = (tabId: NavTab) => {
    onTabChange(tabId);
    onCloseMobile();
  };

  const content = (
    <div className="flex flex-col h-full bg-[#111319] border-r border-[#222733] text-[#d6dbe9] select-none">
      {/* Brand Header */}
      <div className="p-5 border-b border-[#222733]/80 flex items-center justify-between">
        <div
          onClick={() => handleSelectTab('dashboard')}
          className="flex items-center gap-3 cursor-pointer group"
        >
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-purple-600/30 to-teal-500/20 border border-purple-500/40 flex items-center justify-center text-purple-300 shadow-[0_0_16px_rgba(168,85,247,0.2)] group-hover:border-purple-400 transition-colors">
            <Shield className="w-5 h-5 text-purple-300 group-hover:scale-105 transition-transform" />
          </div>
          <div className="flex flex-col">
            <div className="flex items-center gap-1.5">
              <span className="font-bold text-[17px] text-white tracking-tight">PhishGuard</span>
              <span className="text-[10px] font-semibold tracking-wider uppercase px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 font-mono">
                AI
              </span>
            </div>
            <span className="text-[11px] font-medium tracking-wide text-zinc-400 font-mono">
              SOC DEFENSE CORE
            </span>
          </div>
        </div>

        {/* Mobile close button */}
        <button
          onClick={onCloseMobile}
          aria-label="Close menu"
          className="lg:hidden p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-800 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Cluster Status Micro-Card */}
      <div className="px-4 pt-4 pb-2">
        <div className="p-3 rounded-xl bg-[#171a24] border border-[#262c3b] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <span className="relative flex h-2.5 w-2.5">
              <span
                className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                  radarActive ? 'bg-teal-400' : 'bg-zinc-500'
                }`}
              />
              <span
                className={`relative inline-flex rounded-full h-2.5 w-2.5 ${
                  radarActive ? 'bg-teal-500' : 'bg-zinc-500'
                }`}
              />
            </span>
            <div className="flex flex-col">
              <span className="text-[11px] font-semibold text-zinc-200 tracking-wide uppercase">
                {backendOnline ? 'Backend Online' : 'Backend Offline'}
              </span>
              <span className="text-[10px] text-zinc-400 font-mono">
                {backendOnline
                  ? 'API & database services reachable'
                  : 'Start the PhishGuard backend'}
              </span>
            </div>
          </div>
          <div className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${
              backendOnline
                ? 'text-teal-400 bg-teal-500/10 border-teal-500/20'
                : 'text-zinc-400 bg-zinc-500/10 border-zinc-500/20'
            }`}>
            {backendOnline ? 'ONLINE' : 'OFFLINE'}
          </div>
        </div>
      </div>

      {/* Navigation List */}
      <div className="flex-1 px-3 py-3 space-y-1 overflow-y-auto scrollbar-none">
        <div className="px-3 pb-1.5 text-[10px] font-bold uppercase tracking-wider text-zinc-500 font-mono">
          Operations & Intelligence
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              id={`nav-${item.id}`}
              onClick={() => handleSelectTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-left transition-all group ${
                item.active
                  ? 'bg-purple-600/15 text-white border border-purple-500/30 shadow-[0_0_18px_rgba(168,85,247,0.12)]'
                  : 'text-zinc-400 hover:text-zinc-100 hover:bg-[#181c27] border border-transparent'
              }`}
            >
              <div className="flex items-center gap-3 min-w-0">
                <div
                  className={`w-8 h-8 rounded-lg flex items-center justify-center transition-colors ${
                    item.active
                      ? 'bg-purple-500/20 text-purple-300'
                      : 'bg-[#181c27] text-zinc-400 group-hover:text-zinc-200 group-hover:bg-[#202534]'
                  }`}
                >
                  <Icon className="w-4 h-4 shrink-0" />
                </div>
                <div className="flex flex-col min-w-0">
                  <span
                    className={`text-[13px] font-semibold tracking-tight truncate ${
                      item.active ? 'text-white' : 'text-zinc-300 group-hover:text-white'
                    }`}
                  >
                    {item.label}
                  </span>
                  <span className="text-[10px] text-zinc-500 truncate group-hover:text-zinc-400">
                    {item.description}
                  </span>
                </div>
              </div>

              {item.badge && (
                <span
                  className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full shrink-0 ml-1 ${item.badgeClass}`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Bottom Profile & AI Status */}
      <div className="p-3 border-t border-[#222733]/80 space-y-2.5">
        {/* Sentinel AI Prompt Suggestion Card */}
        <div
          onClick={() => handleSelectTab('chatbot')}
          className="p-2.5 rounded-xl bg-gradient-to-r from-purple-950/40 via-purple-900/20 to-transparent border border-purple-500/25 cursor-pointer hover:border-purple-500/40 transition-all group"
        >
          <div className="flex items-center justify-between text-[11px] mb-1">
            <div className="flex items-center gap-1 text-purple-300 font-semibold">
              <Sparkles className="w-3.5 h-3.5 text-purple-400" />
              <span>Sentinel AI</span>
            </div>
            <span className="text-[9px] font-mono text-teal-400 bg-teal-500/10 px-1.5 py-0.2 rounded border border-teal-500/20">
              READY
            </span>
          </div>
          <p className="text-[11px] text-zinc-400 line-clamp-1 group-hover:text-zinc-300">
            Ask about zero-day phishing or inspect payloads...
          </p>
        </div>

       
      </div>
    </div>
  );

  return (
    <>
      {/* Desktop Fixed Left Sidebar */}
      <aside className="hidden lg:block fixed inset-y-0 left-0 w-64 xl:w-72 z-40">
        {content}
      </aside>

      {/* Mobile Drawer (Collapsible) */}
      {mobileOpen && (
        <div className="lg:hidden fixed inset-0 z-50 flex">
          <div
            className="fixed inset-0 bg-black/80 backdrop-blur-sm transition-opacity"
            onClick={onCloseMobile}
          />
          <div className="relative w-72 max-w-[85vw] h-full shadow-2xl z-10 animate-slideRight">
            {content}
          </div>
        </div>
      )}
    </>
  );
}

