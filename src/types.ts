export type NavTab =
  | 'dashboard'
  | 'scanner'
  | 'history'
  | 'chatbot'
  | 'tips'
  | 'settings'
  | 'soc'
  | 'scan'
  | 'logs'
  | 'sentinel'
  | 'config';

export type ThreatVerdict = 'malicious' | 'suspicious' | 'safe';

export interface SecurityFinding {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'SUSPICIOUS' | 'SAFE';
  description: string;
  icon: string;
  highlightText?: string;
  codeSnippet?: string;
}

export interface UrlFeatureMatrixItem {
  id: string;
  label: string;
  tag: string;
  tagType: 'WARN' | 'FLAG' | 'ALERT' | 'DECEPTIVE' | 'CLEAN';
  value: string;
  description: string;
}

export interface TelemetryRecord {
  id: string;
  url: string;
  protocol: string;
  host: string;
  path: string;
  verdict: ThreatVerdict;
  verdictLabel: string;
  score: number;
  trigger: string;
  timestamp: string;
  ip: string;
  tlsInfo: string;
  quarantined?: boolean;
  selected?: boolean;
  details?: {
    confidence: string;
    registrar: string;
    dnsTtl: string;
    domVector: string;
  };
}

export interface PlaybookModule {
  id: string;
  tag: string;
  tagColor: string;
  title: string;
  description: string;
  icon: string;
  fullPlaybook: {
    overview: string;
    detectionStrategy: string[];
    mitigationSteps: string[];
    examplePayload: string;
  };
}

export interface ChatFinding {
  title: string;
  desc: string;
  icon: string;
  type: 'warning' | 'history' | 'hub';
}

export interface ChatMessage {
  id: string;
  sender: 'sentinel' | 'analyst';
  timestamp: string;
  text?: string;
  highlightUrl?: string;
  isStructuredVerdict?: boolean;
  verdictTitle?: string;
  verdictDomain?: string;
  confidence?: string;
  findings?: ChatFinding[];
  recommendation?: string;
  actions?: {
    sinkhole?: boolean;
    shareTicket?: boolean;
  };
}

export interface SystemConfig {
  heuristicSensitivity: 'Aggressive' | 'Balanced' | 'Strict';
  radarClusterActive: boolean;
  homoglyphDetection: boolean;
  neuralOcrScan: boolean;
  autoSinkhole: boolean;
  zeroDayTelemetry: boolean;
  activeRegions: number;
  feeds: {
    alienVault: boolean;
    virusTotal: boolean;
    phishTank: boolean;
    cisaKnown: boolean;
  };
  webhooks: {
    slack: boolean;
    splunk: boolean;
    sentinel: boolean;
    pagerduty: boolean;
  };
}

