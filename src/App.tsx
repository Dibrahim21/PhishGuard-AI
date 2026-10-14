import { useEffect, useState } from 'react';

import {
  NavTab,
  PlaybookModule,
  SystemConfig,
} from './types';

import Sidebar from './components/Sidebar';
import Header from './components/Header';
import SocCommandCenter from './components/SocCommandCenter';
import NeuralUrlScanner from './components/NeuralUrlScanner';
import TelemetryHistory from './components/TelemetryHistory';
import SentinelAiAssistant from './components/SentinelAiAssistant';
import SecurityTipsView from './components/SecurityTipsView';
import ConfigSettings from './components/ConfigSettings';
import PlaybookModal from './components/PlaybookModal';
import AuthScreen from './components/AuthScreen';
import {
  API_ENDPOINTS,
  getAuthHeaders,
  clearStoredAuth,
  AUTH_TOKEN_KEY,
  AUTH_USER_KEY,
} from './config/api';

interface AuthUser {
  id: number;
  email: string;
}


export default function App() {
  /* =========================
      AUTH STATE
  ========================== */

  const [authToken, setAuthToken] =
    useState<string | null>(() =>
      localStorage.getItem(AUTH_TOKEN_KEY)
    );

  const [authUser, setAuthUser] =
    useState<AuthUser | null>(() => {
      const savedUser =
        localStorage.getItem(AUTH_USER_KEY);

      if (!savedUser) {
        return null;
      }

      try {
        return JSON.parse(savedUser);
      } catch {
        return null;
      }
    });

  const [refreshKey, setRefreshKey] =
    useState<number>(0);

  /*
   * Verify session with /api/me on mount or token change
   * Clears invalid/expired tokens so user is not trapped in 401 state
   */
  useEffect(() => {
    if (!authToken) return;

    let isMounted = true;

    const verifySession = async () => {
      try {
        const response = await fetch(API_ENDPOINTS.me, {
          headers: getAuthHeaders(),
        });

        if (!isMounted) return;

        if (response.status === 401) {
          console.warn('Current session token is invalid or expired. Prompting login.');
          clearStoredAuth();
          setAuthToken(null);
          setAuthUser(null);
        } else if (response.ok) {
          const data = await response.json();
          if (data?.user && isMounted) {
            setAuthUser(data.user);
            localStorage.setItem(AUTH_USER_KEY, JSON.stringify(data.user));
          }
        }
      } catch (err) {
        console.warn('Backend reachability check warning:', err);
      }
    };

    void verifySession();

    return () => {
      isMounted = false;
    };
  }, [authToken]);

  /* =========================
      APP STATE
  ========================== */

  const [currentTab, setCurrentTab] =
    useState<NavTab>('dashboard');

  const [targetScanUrl, setTargetScanUrl] =
    useState<string>('');

  const [activePlaybook, setActivePlaybook] =
    useState<PlaybookModule | null>(null);

  const [radarActive, setRadarActive] =
    useState<boolean>(true);

  const [mobileMenuOpen, setMobileMenuOpen] =
    useState<boolean>(false);

  const [toast, setToast] = useState<{
    message: string;
    isAlert?: boolean;
  } | null>(null);

  const [systemConfig, setSystemConfig] =
    useState<SystemConfig>({
      heuristicSensitivity: 'Aggressive',
      radarClusterActive: true,
      homoglyphDetection: true,
      neuralOcrScan: true,
      autoSinkhole: false,
      zeroDayTelemetry: true,
      activeRegions: 6,

      feeds: {
        alienVault: true,
        virusTotal: true,
        phishTank: true,
        cisaKnown: true,
      },

      webhooks: {
        slack: true,
        splunk: true,
        sentinel: true,
        pagerduty: false,
      },
    });

  /* =========================
      LOGIN
  ========================== */

  const handleLogin = (
    token: string,
    user: AuthUser
  ) => {
    localStorage.setItem(
      AUTH_TOKEN_KEY,
      token
    );

    localStorage.setItem(
      AUTH_USER_KEY,
      JSON.stringify(user)
    );

    setAuthToken(token);
    setAuthUser(user);
    setRefreshKey((k) => k + 1);
  };

  /* =========================
      LOGOUT
  ========================== */

  const handleLogout = async () => {
    try {
      const headers = getAuthHeaders();
      if (headers.Authorization) {
        await fetch(
          API_ENDPOINTS.logout,
          {
            method: 'POST',
            headers,
          }
        );
      }
    } catch (error) {
      console.error(
        'Logout error:',
        error
      );
    } finally {
      clearStoredAuth();
      setAuthToken(null);
      setAuthUser(null);
    }
  };


  /* =========================
      TOAST
  ========================== */

  const showToast = (
    message: string,
    isAlert: boolean = false
  ) => {
    setToast({
      message,
      isAlert,
    });

    setTimeout(() => {
      setToast(null);
    }, 3200);
  };

  /* =========================
      EXTERNAL URL → SCANNER
  ========================== */

  const handleScanUrlFromExternal = (
    url: string
  ) => {
    setTargetScanUrl(url);
    setCurrentTab('scanner');
    setMobileMenuOpen(false);
  };

  /* =========================
      OPEN SCANNER
  ========================== */

  const handleOpenScanner = () => {
    setTargetScanUrl('');
    setCurrentTab('scanner');
    setMobileMenuOpen(false);
  };

  /* =========================
      SECURITY TIPS → SCANNER
  ========================== */

  const handleTipsScanner = () => {
    handleOpenScanner();

    showToast(
      'URL Scanner opened. Paste a suspicious website to analyze.'
    );
  };

  /* =========================
      RADAR
  ========================== */

  const handleToggleRadar = () => {
    const next = !radarActive;

    setRadarActive(next);

    showToast(
      next
        ? 'Security monitoring activated'
        : 'Security monitoring paused'
    );
  };

  /* =========================
      TAB NAVIGATION
  ========================== */

  const handleTabChange = (
    tab: NavTab
  ) => {
    setCurrentTab(tab);

    setMobileMenuOpen(false);
  };

  /* =========================
      TAB ALIASES
  ========================== */

  const isDashboard =
    currentTab === 'dashboard' ||
    currentTab === 'soc';

  const isScanner =
    currentTab === 'scanner' ||
    currentTab === 'scan';

  const isHistory =
    currentTab === 'history' ||
    currentTab === 'logs';

  const isChatbot =
    currentTab === 'chatbot' ||
    currentTab === 'sentinel';

  const isTips =
    currentTab === 'tips';

  const isSettings =
    currentTab === 'settings' ||
    currentTab === 'config';

  /* =========================
      AUTH GATE
  ========================== */

  if (!authToken) {
    return (
      <AuthScreen
        onLogin={handleLogin}
      />
    );
  }

  /* =========================
      MAIN APP
  ========================== */

  return (
    <div
      className="
        min-h-screen
        bg-[#0e1117]
        text-[#d6dbe9]
        antialiased
        selection:bg-purple-600
        selection:text-white
        flex
        flex-col
      "
    >

      {/* TOAST */}
      {toast && (
        <div
          role="alert"
          className="
            fixed
            top-5
            left-1/2
            -translate-x-1/2
            z-50
            flex
            items-center
            gap-2.5
            px-4
            py-2.5
            rounded-full
            bg-[#1c2130]
            shadow-2xl
            text-white
            text-xs
            border
            border-[#30394d]
          "
        >
          <span
            className={`
              w-2
              h-2
              rounded-full
              ${toast.isAlert
                ? 'bg-red-400 animate-ping'
                : 'bg-teal-400'
              }
            `}
          />

          <span className="font-medium">
            {toast.message}
          </span>
        </div>
      )}

      {/* SIDEBAR */}
      <Sidebar
        currentTab={currentTab}
        onTabChange={handleTabChange}
        radarActive={radarActive}
        mobileOpen={mobileMenuOpen}
        onCloseMobile={() =>
          setMobileMenuOpen(false)
        }
      />

      {/* MAIN AREA */}
      <div
        className="
          flex-1
          lg:pl-64
          xl:pl-72
          flex
          flex-col
          min-w-0
          min-h-screen
        "
      >

        {/* HEADER */}
        <Header
          currentTab={currentTab}
          onTabChange={handleTabChange}
          radarActive={radarActive}
          onToggleRadar={handleToggleRadar}
          onOpenMobileMenu={() =>
            setMobileMenuOpen(true)
          }
          onQuickScanTrigger={
            handleOpenScanner
          }
          onLogout={handleLogout}
        />

        {/* PAGE CONTENT */}
        <main className="flex-1 pb-12">

          {/* =========================
              DASHBOARD
          ========================== */}

          <div className={isDashboard ? 'block' : 'hidden'}>
            <SocCommandCenter
              key={`dashboard-${refreshKey}`}
              onScanUrl={handleScanUrlFromExternal}
              onOpenPlaybook={(playbook) =>
                setActivePlaybook(playbook)
              }
            />
          </div>

          {/* =========================
              URL SCANNER
          ========================== */}

          {isScanner && (
            <div
              className="
                w-full
                max-w-7xl
                mx-auto
                px-4
                sm:px-6
                lg:px-8
                py-6
              "
            >
              <NeuralUrlScanner
                initialUrl={targetScanUrl}
                onNavigateToLogs={() =>
                  handleTabChange('history')
                }
                onShowToast={showToast}
                onScanComplete={() => {
                  setRefreshKey((k) => k + 1);
                }}
              />
            </div>
          )}

          {/* =========================
              TELEMETRY HISTORY
          ========================== */}

          <div className={isHistory ? 'block' : 'hidden'}>
            <div
              className="
                w-full
                max-w-7xl
                mx-auto
                px-4
                sm:px-6
                lg:px-8
                py-6
              "
            >
              <TelemetryHistory
                key={`history-${refreshKey}`}
                onShowToast={showToast}
                onInspectUrl={handleScanUrlFromExternal}
              />
            </div>
          </div>

          {/* =========================
              AI SECURITY ASSISTANT
          ========================== */}

          {isChatbot && (
            <div
              className="
                w-full
                max-w-7xl
                mx-auto
                px-4
                sm:px-6
                lg:px-8
                py-6
              "
            >
              <SentinelAiAssistant
                onShowToast={showToast}
                onInspectUrl={
                  handleScanUrlFromExternal
                }
              />
            </div>
          )}

          {/* =========================
              SECURITY TIPS
          ========================== */}

          {isTips && (
            <div
              className="
                w-full
                max-w-7xl
                mx-auto
                px-4
                sm:px-6
                lg:px-8
                py-6
              "
            >
              <SecurityTipsView
                onShowToast={showToast}
              />
            </div>
          )}

          {/* =========================
              SETTINGS
          ========================== */}

          {isSettings && (
            <div
              className="
                w-full
                max-w-7xl
                mx-auto
                px-4
                sm:px-6
                lg:px-8
                py-6
              "
            >
              <ConfigSettings
                config={systemConfig}
                onUpdateConfig={
                  setSystemConfig
                }
                onShowToast={showToast}
              />
            </div>
          )}

        </main>
      </div>

      {/* PLAYBOOK MODAL */}

      <PlaybookModal
        playbook={activePlaybook}
        onClose={() =>
          setActivePlaybook(null)
        }
      />

    </div>
  );
}
