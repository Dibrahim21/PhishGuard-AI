import { useState, FormEvent } from 'react';
import { NavTab } from '../types';
import {
  Menu,
  Search,
  Radar,
  User,
} from 'lucide-react';

interface HeaderProps {
  currentTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  radarActive: boolean;
  onToggleRadar: () => void;
  onOpenMobileMenu: () => void;
  onQuickScanTrigger: () => void;
}

export default function Header({
  currentTab,
  onTabChange,
  radarActive,
  onToggleRadar,
  onOpenMobileMenu,
  onQuickScanTrigger,
}: HeaderProps) {
  const [searchVal, setSearchVal] = useState('');

  const getPageInfo = () => {
    switch (currentTab) {
      case 'dashboard':
      case 'soc':
        return {
          title: 'Dashboard',
          subtitle: 'Real-time SOC threat telemetry & analytics',
        };

      case 'scanner':
      case 'scan':
        return {
          title: 'URL Scanner',
          subtitle: 'Neural heuristic & deep DOM inspection',
        };

      case 'history':
      case 'logs':
        return {
          title: 'Scan History',
          subtitle: 'Forensic audit logs & triage records',
        };

      case 'chatbot':
      case 'sentinel':
        return {
          title: 'AI Security Chatbot',
          subtitle: 'Sentinel conversational threat advisor',
        };

      case 'tips':
        return {
          title: 'Security Tips',
          subtitle: 'Defensive playbooks & phishing tactics',
        };

      case 'settings':
      case 'config':
        return {
          title: 'Settings',
          subtitle: 'Autonomous heuristics & SIEM webhooks',
        };

      default:
        return {
          title: 'Dashboard',
          subtitle: 'SOC Command Center',
        };
    }
  };

  const page = getPageInfo();

  const handleSearchSubmit = (e: FormEvent) => {
    e.preventDefault();

    if (!searchVal.trim()) return;

    onTabChange('scanner');
  };

  return (
    <header className="sticky top-0 z-30 w-full bg-[#111319]/90 backdrop-blur-md border-b border-[#222733] px-4 sm:px-6 lg:px-8 py-3.5">
      <div className="flex items-center justify-between gap-4">

        {/* Left: Mobile hamburger & Page Title */}
        <div className="flex items-center gap-3 min-w-0">

          <button
            onClick={onOpenMobileMenu}
            aria-label="Open Navigation Sidebar"
            className="lg:hidden p-2 rounded-xl bg-[#171a24] text-zinc-300 hover:text-white border border-[#262c3b] transition-colors"
          >
            <Menu className="w-5 h-5" />
          </button>

          <div className="flex flex-col min-w-0">

            <div className="flex items-center gap-2">

              <h1 className="text-base sm:text-lg font-bold text-white tracking-tight truncate">
                {page.title}
              </h1>

              <span className="hidden sm:inline-block text-[10px] font-mono px-2 py-0.5 rounded-full bg-teal-500/10 text-teal-400 border border-teal-500/20">
                ACTIVE
              </span>

            </div>

            <span className="text-xs text-zinc-400 truncate hidden md:block">
              {page.subtitle}
            </span>

          </div>
        </div>

        {/* Center: Search / Domain lookup */}
        <form
          onSubmit={handleSearchSubmit}
          className="hidden md:flex flex-1 max-w-md mx-4 relative"
        >
          <Search className="w-4 h-4 text-zinc-400 absolute left-3.5 top-1/2 -translate-y-1/2" />

          <input
            type="text"
            value={searchVal}
            onChange={(e) =>
              setSearchVal(e.target.value)
            }
            placeholder="Search domain, IP, hash or payload..."
            className="w-full pl-9 pr-4 py-2 rounded-xl bg-[#171a24] border border-[#262c3b] text-xs text-white placeholder:text-zinc-500 focus:outline-none focus:border-purple-500 transition-colors font-mono"
          />
        </form>

        {/* Right: Actions & Indicators */}
        <div className="flex items-center gap-3 shrink-0">

          {/* Scan URL Quick Action Button */}
          <button
            onClick={onQuickScanTrigger}
            className="px-3.5 py-2 rounded-xl bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold shadow-[0_0_16px_rgba(168,85,247,0.25)] flex items-center gap-1.5 active:scale-95 transition-all cursor-pointer"
          >
            <Radar className="w-3.5 h-3.5 text-purple-200" />

            <span className="hidden sm:inline">
              Scan URL
            </span>
          </button>

          {/* Autonomous Radar Status Badge */}
          <button
            onClick={onToggleRadar}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl border text-xs font-mono font-semibold transition-all cursor-pointer ${
              radarActive
                ? 'bg-teal-500/10 text-teal-400 border-teal-500/30'
                : 'bg-zinc-800 text-zinc-400 border-zinc-700'
            }`}
            title="Toggle autonomous surveillance radar"
          >
            <span
              className={`w-2 h-2 rounded-full ${
                radarActive
                  ? 'bg-teal-400 animate-pulse'
                  : 'bg-zinc-500'
              }`}
            />

            <span className="hidden sm:inline">
              {radarActive
                ? 'RADAR ACTIVE'
                : 'RADAR PAUSED'}
            </span>
          </button>

          {/* User Profile / Account Settings */}
          <button
            onClick={() =>
              onTabChange('settings')
            }
            aria-label="User Profile & Settings"
            className="w-9 h-9 rounded-xl bg-[#171a24] border border-[#262c3b] flex items-center justify-center text-zinc-300 hover:text-white hover:border-purple-500/50 hover:bg-[#1c2130] transition-all cursor-pointer shrink-0"
            title="User Profile & Settings"
          >
            <User className="w-4 h-4" />
          </button>


        </div>
      </div>
    </header>
  );
}
