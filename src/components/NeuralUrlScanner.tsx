import { useEffect, useState } from 'react';
import { jsPDF } from 'jspdf';

interface NeuralUrlScannerProps {
  initialUrl?: string;
  onNavigateToLogs?: () => void;
  onNavigateToTips?: () => void;
  onShowToast: (
    msg: string,
    isAlert?: boolean
  ) => void;
}

type FindingSeverity =
  | 'CRITICAL'
  | 'HIGH'
  | 'SUSPICIOUS'
  | 'LOW'
  | 'INFO';

type Finding = {
  id: string;
  title: string;
  severity: FindingSeverity;
  description: string;
  icon: string;
};

type UrlFeature = {
  id: string;
  label: string;
  value: string;
  description: string;
  tag: string;
};

type BackendAnalysis = {
  url: string;
  score: number;
  verdict: 'safe' | 'suspicious' | 'malicious';
  verdictLabel: string;
  confidence: string;
  threatBannerTitle: string;
  threatBannerDesc: string;

  host: string;

  domainAge: string;
  domainAgeLabel: string;

  heuristicsPercent: string;
  heuristicsLabel: string;

  cloneMatchPercent: string;
  cloneMatchLabel: string;

  findings: Finding[];
  features: UrlFeature[];

  tlsState: {
    title: string;
    trustStatus: string;
    description: string;
  };

  targetBrand: string;
  similarity: string;

  backend: BackendScanResponse;
};

type BackendScanResponse = {
  scan_id: number;
  status: string;
  message?: string;
  url: string;

  verdict: 'Legitimate' | 'Suspicious' | 'Phishing';

  risk_score: number;
  model_probability: number;
  phishing_probability: number;
  legitimate_probability: number;

  prediction: number;

  domain_reputation?: string;

  domain_info?: {
    hostname?: string;
    registrable_domain?: string;
    subdomain?: string;
    tld?: string;
    scheme?: string;

    is_ip_address?: boolean;
    dns_resolved?: boolean;
    ip_address?: string;

    allowlist_match?: string | null;

    brand_impersonation?: {
      detected?: boolean;
      brand?: string | null;
      confidence?: number;
      legitimate_domain?: string | null;
      matched_text?: string | null;
      match_type?: string | null;
      has_context?: boolean;
      reason?: string | null;
    };
  };

  ssl_analysis?: {
    certificate_available?: boolean;
    certificate_valid?: boolean;
    hostname_match?: boolean;
    https_enabled?: boolean;

    issuer?: string;
    subject?: string;

    valid_from?: string;
    valid_until?: string;

    days_until_expiry?: number | null;

    status?: string;
  };

  signals?: {
    ml_model?: string;
    domain_reputation?: string;
    suspicious_tld?: string;

    keyword_risk?: string;

    hostname_risk?: string;

    excessive_hyphens?: boolean;
    excessive_subdomains?: boolean;

    at_symbol?: boolean;
    encoded_characters?: boolean;

    is_url_shortener?: boolean;
    non_standard_port?: boolean;

    dns_resolved?: boolean;

    https?: string;

    ssl?: string;

    brand_impersonation?: string;
  };

  score_breakdown?: Record<
    string,
    number
  >;

  reasons?: string[];

  features?: Record<
    string,
    number | string | boolean | string[]
  >;
}

const API_URL =
  'https://phishguard-ai-85s9.onrender.com/api/scan';

const getAuthHeaders = (): Record<string, string> => {
  const token = localStorage.getItem('phishguard_token') || '';

  return token
    ? { Authorization: `Bearer ${token}` }
    : {};
};

export default function NeuralUrlScanner({
  initialUrl,
  onNavigateToLogs,
  onNavigateToTips,
  onShowToast,
}: NeuralUrlScannerProps) {
  const [urlInput, setUrlInput] =
    useState(initialUrl || '');

  const [isAnalyzing, setIsAnalyzing] =
    useState(false);

  const [analysis, setAnalysis] =
    useState<BackendAnalysis | null>(null);

  const [quarantined, setQuarantined] =
    useState(false);

  useEffect(() => {
    if (initialUrl) {
      setUrlInput(initialUrl);
      setAnalysis(null);
      setQuarantined(false);
    }
  }, [initialUrl]);

  const normalizeUrl = (
    value: string
  ) => {
    const trimmed =
      value.trim();

    if (!trimmed) {
      return '';
    }

    if (
      !trimmed.startsWith('http://') &&
      !trimmed.startsWith('https://')
    ) {
      return `https://${trimmed}`;
    }

    return trimmed;
  };

  /*
   * BACKEND RESPONSE → FRONTEND UI
   */

  const convertBackendResult = (
    data: BackendScanResponse
  ): BackendAnalysis => {
    const risk =
      Number(data.risk_score ?? 0);

    const backendVerdict =
      String(
        data.verdict || ''
      ).toLowerCase();

    const verdict:
      BackendAnalysis['verdict'] =
      backendVerdict === 'phishing'
        ? 'malicious'
        : backendVerdict === 'suspicious'
          ? 'suspicious'
          : 'safe';

    const verdictLabel =
      backendVerdict === 'phishing'
        ? 'Phishing'
        : backendVerdict === 'suspicious'
          ? 'Suspicious'
          : 'Legitimate';

    const domainInfo =
      data.domain_info || {};

    const signals =
      data.signals || {};

    const reasons =
      Array.isArray(data.reasons)
        ? data.reasons
        : [];

    const findings: Finding[] = [];

    /*
     * BRAND IMPERSONATION
     */

    const brand =
      domainInfo.brand_impersonation;

    if (brand?.detected) {
      findings.push({
        id: 'brand-impersonation',
        title: 'Brand Impersonation Detected',
        severity: 'CRITICAL',
        description:
          brand.reason ||
          `Possible ${brand.brand || 'brand'} impersonation detected.`,
        icon: 'branding_watermark',
      });
    }

    /*
     * SUSPICIOUS TLD
     */

    if (
      signals.suspicious_tld ===
      'detected'
    ) {
      findings.push({
        id: 'suspicious-tld',
        title: 'Suspicious TLD',
        severity: 'HIGH',
        description:
          'The domain uses a TLD associated with elevated phishing risk.',
        icon: 'language',
      });
    }

    /*
     * KEYWORD RISK
     */

    if (
      signals.keyword_risk ===
      'high'
    ) {
      findings.push({
        id: 'keyword-risk-high',
        title: 'Phishing Keywords Detected',
        severity: 'HIGH',
        description:
          'Multiple phishing-related keywords were detected in the URL.',
        icon: 'warning',
      });
    } else if (
      signals.keyword_risk ===
      'medium'
    ) {
      findings.push({
        id: 'keyword-risk-medium',
        title: 'Suspicious Keywords',
        severity: 'SUSPICIOUS',
        description:
          'The URL contains keywords commonly associated with account or credential attacks.',
        icon: 'search',
      });
    }

    /*
     * HYPHENS
     */

    if (
      signals.excessive_hyphens
    ) {
      findings.push({
        id: 'hyphens',
        title: 'Excessive Hyphens',
        severity: 'SUSPICIOUS',
        description:
          'The hostname contains an unusually high number of hyphens.',
        icon: 'remove',
      });
    }

    /*
     * SUBDOMAINS
     */

    if (
      signals.excessive_subdomains
    ) {
      findings.push({
        id: 'subdomains',
        title: 'Excessive Subdomains',
        severity: 'SUSPICIOUS',
        description:
          'The hostname contains an unusually large number of subdomains.',
        icon: 'account_tree',
      });
    }

    /*
     * URL SHORTENER
     */

    if (
      signals.is_url_shortener
    ) {
      findings.push({
        id: 'shortener',
        title: 'URL Shortener Detected',
        severity: 'SUSPICIOUS',
        description:
          'The URL uses a known URL shortening service.',
        icon: 'link',
      });
    }

    /*
     * @ SYMBOL
     */

    if (
      signals.at_symbol
    ) {
      findings.push({
        id: 'at-symbol',
        title: '@ Symbol Detected',
        severity: 'HIGH',
        description:
          'The URL contains an @ symbol, which can be abused to disguise the actual destination.',
        icon: 'alternate_email',
      });
    }

    /*
     * NON STANDARD PORT
     */

    if (
      signals.non_standard_port
    ) {
      findings.push({
        id: 'port',
        title: 'Non-standard Port',
        severity: 'SUSPICIOUS',
        description:
          'The URL uses a non-standard network port.',
        icon: 'lan',
      });
    }

    /*
     * ENCODED CHARACTERS
     */

    if (
      signals.encoded_characters
    ) {
      findings.push({
        id: 'encoded',
        title: 'Encoded Characters',
        severity: 'SUSPICIOUS',
        description:
          'Encoded characters were detected in the URL.',
        icon: 'code',
      });
    }

    /*
     * DNS
     */

    if (
      signals.dns_resolved ===
      false
    ) {
      findings.push({
        id: 'dns',
        title: 'DNS Resolution Failed',
        severity: 'SUSPICIOUS',
        description:
          'The domain could not be resolved through DNS during the scan.',
        icon: 'dns',
      });
    }

    /*
     * IP ADDRESS
     */

    if (
      domainInfo.is_ip_address
    ) {
      findings.push({
        id: 'ip-host',
        title: 'IP Address Used as Host',
        severity: 'HIGH',
        description:
          'The URL uses an IP address instead of a normal domain name.',
        icon: 'router',
      });
    }

    /*
     * HTTP
     */

    if (
      domainInfo.scheme ===
      'http'
    ) {
      findings.push({
        id: 'no-https',
        title: 'HTTPS Not Enabled',
        severity: 'SUSPICIOUS',
        description:
          'The URL uses HTTP instead of HTTPS.',
        icon: 'lock_open',
      });
    }

    /*
     * SSL / TLS
     */

    const ssl =
      data.ssl_analysis;

    if (
      ssl?.status ===
      'hostname_mismatch'
    ) {
      findings.push({
        id: 'ssl-hostname-mismatch',
        title: 'TLS Hostname Mismatch',
        severity: 'HIGH',
        description:
          'The TLS certificate does not match the requested hostname.',
        icon: 'gpp_bad',
      });
    }

    if (
      ssl?.status ===
      'invalid'
    ) {
      findings.push({
        id: 'ssl-invalid',
        title: 'Invalid TLS Certificate',
        severity: 'HIGH',
        description:
          'The TLS certificate failed certificate validity checks.',
        icon: 'lock_open',
      });
    }

    if (
      ssl?.status ===
      'certificate_unavailable'
    ) {
      findings.push({
        id: 'ssl-unavailable',
        title: 'TLS Certificate Unavailable',
        severity: 'SUSPICIOUS',
        description:
          'A TLS certificate could not be retrieved during analysis.',
        icon: 'lock',
      });
    }

    /*
     * NO FINDINGS
     */

    if (
      findings.length === 0
    ) {
      findings.push({
        id: 'clean',
        title: 'No Major Suspicious Indicators',
        severity: 'INFO',
        description:
          'No major suspicious URL indicators were detected by the current analysis pipeline.',
        icon: 'verified',
      });
    }

    /*
     * URL FEATURE ANALYSIS
     */

    const rawFeatures =
      data.features || {};

    const features: UrlFeature[] = [
      {
        id: 'url-length',
        label: 'URL Length',
        value:
          `${rawFeatures.url_length ?? 0} characters`,
        description:
          'Total length of the submitted URL.',
        tag:
          Number(
            rawFeatures.url_length ?? 0
          ) > 100
            ? 'HIGH'
            : 'NORMAL',
      },

      {
        id: 'hostname-length',
        label: 'Hostname Length',
        value:
          `${rawFeatures.hostname_length ?? 0} characters`,
        description:
          'Length of the hostname portion.',
        tag:
          rawFeatures.long_hostname
            ? 'SUSPICIOUS'
            : 'NORMAL',
      },

      {
        id: 'subdomains',
        label: 'Subdomains',
        value:
          `${rawFeatures.subdomain_count ?? 0}`,
        description:
          'Number of detected subdomain levels.',
        tag:
          rawFeatures.many_subdomains
            ? 'SUSPICIOUS'
            : 'NORMAL',
      },

      {
        id: 'hyphens',
        label: 'Hyphens',
        value:
          `${rawFeatures.hyphen_count ?? 0}`,
        description:
          'Number of hyphens detected in the URL.',
        tag:
          rawFeatures.many_hyphens
            ? 'SUSPICIOUS'
            : 'NORMAL',
      },

      {
        id: 'digits',
        label: 'Digits',
        value:
          `${rawFeatures.total_digit_count ?? 0}`,
        description:
          'Total number of digits detected.',
        tag:
          Number(
            rawFeatures.digit_ratio ?? 0
          ) > 0.15
            ? 'SUSPICIOUS'
            : 'NORMAL',
      },

      {
        id: 'keywords',
        label: 'Phishing Keywords',
        value:
          `${rawFeatures.keyword_count ?? 0}`,
        description:
          'Number of phishing-related keywords detected.',
        tag:
          Number(
            rawFeatures.keyword_count ?? 0
          ) >= 3
            ? 'HIGH'
            : Number(
              rawFeatures.keyword_count ?? 0
            ) > 0
              ? 'WATCH'
              : 'NONE',
      },

      {
        id: 'tld',
        label: 'TLD',
        value:
          domainInfo.tld
            ? `.${domainInfo.tld}`
            : 'Unknown',
        description:
          'Top-level domain of the hostname.',
        tag:
          rawFeatures.suspicious_tld
            ? 'SUSPICIOUS'
            : 'NORMAL',
      },

      {
        id: 'https',
        label: 'HTTPS',
        value:
          domainInfo.scheme === 'https'
            ? 'Enabled'
            : 'Not enabled',
        description:
          'Transport security detected from the submitted URL.',
        tag:
          domainInfo.scheme === 'https'
            ? 'SECURE'
            : 'WATCH',
      },

      {
        id: 'entropy',
        label: 'URL Entropy',
        value:
          `${rawFeatures.url_entropy ?? 0}`,
        description:
          'Randomness/complexity measurement of the URL.',
        tag:
          Number(
            rawFeatures.url_entropy ?? 0
          ) > 4.5
            ? 'HIGH'
            : 'NORMAL',
      },

      {
        id: 'dns',
        label: 'DNS Resolution',
        value:
          domainInfo.dns_resolved
            ? 'Resolved'
            : 'Not Resolved',
        description:
          'Whether the hostname resolved through DNS.',
        tag:
          domainInfo.dns_resolved
            ? 'NORMAL'
            : 'WATCH',
      },
    ];

    /*
     * SSL / TLS UI
     */

    const tlsState = {
      title:
        ssl?.status === 'valid'
          ? 'TLS Certificate Valid'
          : ssl?.status ===
            'hostname_mismatch'
            ? 'TLS Hostname Mismatch'
            : ssl?.status ===
              'invalid'
              ? 'Invalid TLS Certificate'
              : domainInfo.scheme ===
                'https'
                ? 'TLS Analysis'
                : 'HTTPS Not Enabled',

      trustStatus:
        ssl?.status === 'valid'
          ? 'CERTIFICATE VALID'
          : ssl?.status
            ? ssl.status
              .replace(/_/g, ' ')
              .toUpperCase()
            : domainInfo.scheme ===
              'https'
              ? 'ANALYSIS AVAILABLE'
              : 'NOT ENABLED',

      description:
        ssl?.status === 'valid'
          ? `Certificate matches the hostname. Issuer: ${ssl.issuer || 'Unknown'
          }. ${ssl.days_until_expiry != null
            ? `${ssl.days_until_expiry} days until expiry.`
            : ''
          }`
          : ssl?.status ===
            'hostname_mismatch'
            ? 'The TLS certificate does not match the requested hostname.'
            : ssl?.status ===
              'invalid'
              ? 'The TLS certificate failed validity checks.'
              : domainInfo.scheme ===
                'https'
                ? `TLS status: ${ssl?.status ||
                'unknown'
                }.`
                : 'The submitted URL does not use HTTPS.',
    };

    /*
     * BRAND IMPERSONATION
     *
     * IMPORTANT:
     * We only show a brand when the backend
     * actually detects one.
     */

    const detectedBrand =
      domainInfo
        .brand_impersonation;

    const targetBrand =
      detectedBrand?.detected
        ? detectedBrand.brand ||
        ''
        : '';

    const similarity =
      detectedBrand?.detected
        ? `${detectedBrand.confidence ?? 0}% confidence`
        : 'No brand impersonation detected';

    /*
     * CONFIDENCE
     */

    const phishingProbability =
      Number(
        data.phishing_probability ?? 0
      );

    const confidence =
      `${Math.max(
        phishingProbability,
        100 - phishingProbability
      ).toFixed(2)}%`;

    return {
      url: data.url,

      score:
        Number(
          risk.toFixed(2)
        ),

      verdict,

      verdictLabel,

      confidence,

      threatBannerTitle:
        verdict === 'malicious'
          ? 'Potential Phishing Website Detected'
          : verdict === 'suspicious'
            ? 'Suspicious Website Detected'
            : 'Website Appears Legitimate',

      threatBannerDesc:
        verdict === 'malicious'
          ? 'The backend detection pipeline identified multiple indicators associated with phishing activity.'
          : verdict === 'suspicious'
            ? 'The backend detection pipeline identified some suspicious indicators that require caution.'
            : 'The backend detection pipeline did not identify major suspicious indicators in this URL.',

      host:
        domainInfo.hostname ||
        new URL(data.url).hostname,

      domainAge:
        'Not available',

      domainAgeLabel:
        'Not checked',

      heuristicsPercent:
        `${Math.round(risk)}%`,

      heuristicsLabel:
        'Backend risk score',

      cloneMatchPercent:
        detectedBrand?.detected
          ? `${detectedBrand.confidence ?? 0}%`
          : 'Not available',

      cloneMatchLabel:
        detectedBrand?.detected
          ? 'Brand Match Confidence'
          : 'No Brand Match',

      findings,

      features,

      tlsState,

      targetBrand,

      similarity,

      backend: data,
    };
  };

  /*
   * REAL BACKEND SCAN
   */

  const handleScan = async () => {
    const target =
      normalizeUrl(urlInput);

    if (!target) {
      onShowToast(
        'Please enter a URL to scan.',
        true
      );
      return;
    }

    try {
      new URL(target);
    } catch {
      onShowToast(
        'Please enter a valid URL.',
        true
      );
      return;
    }

    setUrlInput(target);
    setIsAnalyzing(true);
    setAnalysis(null);
    setQuarantined(false);

    try {
      const response =
        await fetch(
          API_URL,
          {
            method: 'POST',

            headers: {
              'Content-Type':
                'application/json',
              ...getAuthHeaders(),
            },

            body:
              JSON.stringify({
                url: target,
              }),
          }
        );

      if (!response.ok) {
        let message =
          'Backend scan failed.';

        try {
          const errorData =
            await response.json();

          if (
            errorData?.message
          ) {
            message =
              errorData.message;
          }
        } catch {
          // Ignore JSON parsing errors.
        }

        throw new Error(
          message
        );
      }

      const data:
        BackendScanResponse =
        await response.json();

      if (
        data.status !==
        'success'
      ) {
        throw new Error(
          data.message ||
          'Unable to analyze this URL.'
        );
      }

      const result =
        convertBackendResult(
          data
        );

      setAnalysis(
        result
      );

      onShowToast(
        `Scan completed: ${result.score}/100 (${result.verdictLabel})`,
        result.verdict ===
        'malicious'
      );

    } catch (error) {
      console.error(
        'Backend scan error:',
        error
      );

      const message =
        error instanceof Error
          ? error.message
          : 'Unable to connect to PhishGuard backend.';

      onShowToast(
        message.includes(
          'Failed to fetch'
        )
          ? 'Unable to connect to PhishGuard backend. Make sure Flask is running on port 5000.'
          : message,
        true
      );

    } finally {
      setIsAnalyzing(false);
    }
  };

  /*
   * PASTE
   */

  const handlePaste =
    async () => {
      try {
        const text =
          await navigator.clipboard.readText();

        if (text) {
          setUrlInput(
            text.trim()
          );

          onShowToast(
            'URL pasted successfully.'
          );
        }
      } catch {
        onShowToast(
          'Clipboard access failed. Please paste manually.',
          true
        );
      }
    };

  /*
   * CLEAR
   */

  const handleClear = () => {
    setUrlInput('');
    setAnalysis(null);
    setQuarantined(false);
  };

  /*
   * QUARANTINE
   *
   * Local UI state only.
   * Does NOT claim real network quarantine.
   */

  const handleQuarantine = () => {
    if (!analysis) {
      return;
    }

    const nextState =
      !quarantined;

    setQuarantined(
      nextState
    );

    if (nextState) {
      onShowToast(
        `${analysis.host} added to local quarantine list.`,
        true
      );
    } else {
      onShowToast(
        `${analysis.host} removed from local quarantine list.`
      );
    }
  };

  /*
   * PDF REPORT
   */

  const handleExportReport = () => {
    if (!analysis) {
      onShowToast(
        'Scan a URL before exporting a report.',
        true
      );
      return;
    }

    try {
      const pdf =
        new jsPDF();

      const pageWidth =
        pdf.internal.pageSize.getWidth();

      const pageHeight =
        pdf.internal.pageSize.getHeight();

      let y = 20;

      const checkPageSpace =
        (
          space: number = 15
        ) => {
          if (
            y >
            pageHeight - space
          ) {
            pdf.addPage();
            y = 20;
          }
        };

      const addText = (
        text: string,
        size: number = 10,
        bold: boolean = false
      ) => {
        pdf.setFontSize(size);

        pdf.setFont(
          'helvetica',
          bold
            ? 'bold'
            : 'normal'
        );

        const lines =
          pdf.splitTextToSize(
            text,
            pageWidth - 30
          );

        lines.forEach(
          (
            line: string
          ) => {
            checkPageSpace(
              size + 8
            );

            pdf.text(
              line,
              15,
              y
            );

            y +=
              size + 3;
          }
        );
      };

      /*
       * HEADER
       */

      pdf.setFillColor(
        20,
        27,
        43
      );

      pdf.rect(
        0,
        0,
        pageWidth,
        38,
        'F'
      );

      pdf.setTextColor(
        79,
        219,
        200
      );

      pdf.setFontSize(
        20
      );

      pdf.setFont(
        'helvetica',
        'bold'
      );

      pdf.text(
        'PHISHGUARD AI',
        15,
        17
      );

      pdf.setFontSize(
        10
      );

      pdf.setTextColor(
        255,
        255,
        255
      );

      pdf.text(
        'Intelligent Phishing Website Detection System',
        15,
        25
      );

      pdf.text(
        'Website Security Scan Report',
        15,
        32
      );

      y = 52;

      pdf.setTextColor(
        30,
        30,
        30
      );

      /*
       * SCAN INFORMATION
       */

      addText(
        'SCAN INFORMATION',
        15,
        true
      );

      y += 3;

      addText(
        `Scan Date: ${new Date().toLocaleString()}`
      );

      addText(
        `Scanned URL: ${analysis.url}`
      );

      addText(
        `Domain: ${analysis.host}`
      );

      y += 6;

      /*
       * VERDICT
       */

      addText(
        'SECURITY VERDICT',
        15,
        true
      );

      y += 3;

      addText(
        `Verdict: ${analysis.verdictLabel}`,
        12,
        true
      );

      addText(
        `Risk Score: ${analysis.score}/100`,
        12,
        true
      );

      addText(
        `ML Phishing Probability: ${analysis.backend
          ?.phishing_probability ??
        'N/A'
        }%`
      );

      addText(
        `Assessment: ${analysis.threatBannerTitle}`
      );

      addText(
        analysis.threatBannerDesc
      );

      y += 6;

      /*
       * DETECTION REASONS
       */

      addText(
        'DETECTION REASONS',
        15,
        true
      );

      y += 3;

      if (
        analysis.backend?.reasons &&
        analysis.backend.reasons.length >
        0
      ) {
        analysis.backend.reasons.forEach(
          (
            reason: string,
            index: number
          ) => {
            addText(
              `${index + 1}. ${reason}`
            );

            y += 1;
          }
        );
      } else {
        analysis.findings.forEach(
          (
            finding,
            index
          ) => {
            addText(
              `${index + 1}. ${finding.title} (${finding.severity})`,
              11,
              true
            );

            addText(
              finding.description
            );
          }
        );
      }

      y += 6;

      /*
       * URL FEATURES
       */

      addText(
        'URL FEATURE ANALYSIS',
        15,
        true
      );

      y += 3;

      analysis.features.forEach(
        (
          feature,
          index
        ) => {
          addText(
            `${index + 1}. ${feature.label}: ${feature.value}`,
            11,
            true
          );

          addText(
            `Details: ${feature.description}`
          );

          addText(
            `Classification: ${feature.tag}`
          );

          y += 2;
        }
      );

      y += 6;

      /*
       * SSL
       */

      addText(
        'SSL / TLS SECURITY CHECK',
        15,
        true
      );

      y += 3;

      addText(
        `Status: ${analysis.tlsState.title}`,
        11,
        true
      );

      addText(
        `Trust Status: ${analysis.tlsState.trustStatus}`
      );

      addText(
        analysis.tlsState.description
      );

      if (
        analysis.backend.ssl_analysis
      ) {
        addText(
          `Certificate Subject: ${analysis.backend
            .ssl_analysis.subject ||
          'N/A'
          }`
        );

        addText(
          `Certificate Issuer: ${analysis.backend
            .ssl_analysis.issuer ||
          'N/A'
          }`
        );

        addText(
          `Hostname Match: ${analysis.backend
            .ssl_analysis.hostname_match
            ? 'Yes'
            : 'No'
          }`
        );

        if (
          analysis.backend
            .ssl_analysis
            .days_until_expiry !=
          null
        ) {
          addText(
            `Days Until Expiry: ${analysis.backend
              .ssl_analysis
              .days_until_expiry
            }`
          );
        }
      }

      y += 6;

      /*
       * DOMAIN INTELLIGENCE
       */

      addText(
        'DOMAIN INTELLIGENCE',
        15,
        true
      );

      y += 3;

      addText(
        `Registrable Domain: ${analysis.backend
          ?.domain_info
          ?.registrable_domain ||
        'N/A'
        }`
      );

      addText(
        `Hostname: ${analysis.backend
          ?.domain_info
          ?.hostname ||
        'N/A'
        }`
      );

      addText(
        `DNS Resolved: ${analysis.backend
          ?.domain_info
          ?.dns_resolved
          ? 'Yes'
          : 'No'
        }`
      );

      addText(
        `Domain Reputation: ${analysis.backend
          ?.domain_reputation ||
        'Unknown'
        }`
      );

      y += 6;

      /*
       * BRAND
       */

      addText(
        'BRAND IMPERSONATION ANALYSIS',
        15,
        true
      );

      y += 3;

      addText(
        `Detected Brand: ${analysis.targetBrand ||
        'No brand impersonation detected'
        }`
      );

      addText(
        `Assessment: ${analysis.similarity
        }`
      );

      if (
        analysis.backend
          ?.domain_info
          ?.brand_impersonation
          ?.reason
      ) {
        addText(
          analysis.backend
            .domain_info
            .brand_impersonation
            .reason
        );
      }

      y += 10;

      checkPageSpace(
        25
      );

      pdf.setFontSize(
        9
      );

      pdf.setTextColor(
        100,
        100,
        100
      );

      pdf.text(
        'Generated by PhishGuard AI - Intelligent Phishing Website Detection System',
        15,
        y
      );

      pdf.save(
        `phishguard-security-report-${Date.now()}.pdf`
      );

      onShowToast(
        'PDF security report downloaded successfully.'
      );

    } catch (error) {
      console.error(
        'PDF generation error:',
        error
      );

      onShowToast(
        'Unable to generate PDF report.',
        true
      );
    }
  };

  /*
   * VERDICT COLORS
   */

  const getVerdictColor = () => {
    if (!analysis) {
      return 'text-[#958ea0]';
    }

    if (
      analysis.verdict ===
      'malicious'
    ) {
      return 'text-[#ff5451]';
    }

    if (
      analysis.verdict ===
      'suspicious'
    ) {
      return 'text-[#f59e0b]';
    }

    return 'text-[#4fdbc8]';
  };

  const getVerdictBackground = () => {
    if (!analysis) {
      return 'bg-[#191f2f] border-[#232a3a]';
    }

    if (
      analysis.verdict ===
      'malicious'
    ) {
      return 'bg-red-950/30 border-red-500/40';
    }

    if (
      analysis.verdict ===
      'suspicious'
    ) {
      return 'bg-orange-950/30 border-orange-500/40';
    }

    return 'bg-teal-950/30 border-teal-500/40';
  };

  const circumference =
    314.159;

  const strokeOffset =
    analysis
      ? circumference -
      (Math.min(
        Math.max(
          analysis.score,
          0
        ),
        100
      ) /
        100) *
      circumference
      : circumference;

  return (
    <div className="flex flex-col w-full max-w-5xl mx-auto px-4 py-4 gap-6 text-[#dce2f7]">

      {/* HEADER */}

      <section className="flex flex-col gap-4">

        <div className="flex items-center justify-between gap-4">

          <div className="flex items-center gap-3">

            <div className="w-10 h-10 rounded-xl bg-teal-500/10 border border-teal-500/20 flex items-center justify-center">

              <span className="material-symbols-outlined text-[#4fdbc8]">
                travel_explore
              </span>

            </div>

            <div>

              <h1 className="text-lg font-bold text-white">
                URL Scanner
              </h1>

              <p className="text-xs text-[#958ea0]">
                Analyze suspicious websites for phishing threats.
              </p>

            </div>

          </div>

          <span className="font-mono text-[10px] text-[#4fdbc8] px-3 py-1.5 bg-[#4fdbc8]/10 border border-[#4fdbc8]/20 rounded-full whitespace-nowrap">
            PHISHGUARD AI
          </span>

        </div>

        {/* URL INPUT */}

        <div className="relative flex items-center bg-[#070e1d] rounded-xl shadow-lg p-2 border border-[#232a3a] focus-within:border-[#a078ff] transition-all">

          <span className="material-symbols-outlined text-[#4fdbc8] text-[20px] ml-2">
            link
          </span>

          <input
            type="text"
            value={urlInput}
            onChange={(event) =>
              setUrlInput(
                event.target.value
              )
            }
            onKeyDown={(event) => {
              if (
                event.key ===
                'Enter'
              ) {
                handleScan();
              }
            }}
            placeholder="Paste a suspicious URL here..."
            className="w-full bg-transparent px-3 py-2 text-sm text-white focus:outline-none placeholder:text-[#958ea0]"
          />

          {urlInput && (
            <button
              type="button"
              onClick={
                handleClear
              }
              className="w-8 h-8 flex items-center justify-center text-[#958ea0] hover:text-white transition-colors"
            >
              <span className="material-symbols-outlined">
                close
              </span>
            </button>
          )}

        </div>

        {/* BUTTONS */}

        <div className="flex flex-col sm:flex-row gap-3">

          <button
            type="button"
            onClick={
              handlePaste
            }
            className="flex-1 h-11 flex items-center justify-center gap-2 bg-[#191f2f] hover:bg-[#232a3a] border border-[#232a3a] rounded-xl text-sm font-medium transition-all"
          >

            <span className="material-symbols-outlined text-[18px]">
              content_paste
            </span>

            Paste URL

          </button>

          <button
            type="button"
            onClick={
              handleScan
            }
            disabled={
              isAnalyzing
            }
            className="flex-[1.5] h-11 flex items-center justify-center gap-2 bg-gradient-to-r from-[#7c3aed] to-[#14b8a6] hover:brightness-110 text-white rounded-xl font-bold text-sm transition-all disabled:opacity-50"
          >

            <span
              className={`material-symbols-outlined ${isAnalyzing
                  ? 'animate-spin'
                  : ''
                }`}
            >
              {isAnalyzing
                ? 'refresh'
                : 'radar'}
            </span>

            {isAnalyzing
              ? 'Analyzing...'
              : 'Scan Website'}

          </button>

        </div>

        {/* SECURITY TIPS */}

        <section className="rounded-2xl border border-purple-500/20 bg-gradient-to-r from-purple-950/30 via-[#141b2b] to-[#141b2b] p-4">

          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">

            <div className="flex items-center gap-3">

              <div className="w-11 h-11 rounded-xl bg-purple-500/15 border border-purple-500/30 flex items-center justify-center">

                <span className="material-symbols-outlined text-purple-300">
                  lightbulb
                </span>

              </div>

              <div>

                <h3 className="text-sm font-bold text-white">
                  Security Tips & Awareness
                </h3>

                <p className="text-xs text-[#958ea0] mt-1">
                  Learn how to identify phishing websites and protect yourself online.
                </p>

              </div>

            </div>

            <button
              type="button"
              onClick={() => {
                if (
                  onNavigateToTips
                ) {
                  onNavigateToTips();
                } else {
                  onShowToast(
                    'Security Tips navigation is not configured.',
                    true
                  );
                }
              }}
              className="shrink-0 h-10 px-4 rounded-xl bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold flex items-center justify-center gap-2 transition-all active:scale-95"
            >

              <span className="material-symbols-outlined text-[18px]">
                arrow_forward
              </span>

              View Security Tips

            </button>

          </div>

        </section>

      </section>

      {/* EMPTY STATE */}

      {!analysis &&
        !isAnalyzing && (

          <section className="rounded-2xl bg-[#141b2b] border border-[#232a3a] min-h-[380px] flex flex-col items-center justify-center text-center p-8">

            <div className="w-20 h-20 rounded-2xl bg-gradient-to-br from-purple-500/20 to-teal-500/20 border border-purple-500/20 flex items-center justify-center mb-5">

              <span className="material-symbols-outlined text-4xl text-[#a078ff]">
                shield
              </span>

            </div>

            <h2 className="text-xl font-bold text-white">
              Ready to Scan
            </h2>

            <p className="text-sm text-[#958ea0] max-w-md mt-3">
              Enter a website URL above to analyze phishing indicators,
              risk score, security findings, SSL status and brand
              impersonation.
            </p>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-8 w-full max-w-3xl">

              {[
                'URL Analysis',
                'Risk Score',
                'SSL Check',
                'Brand Detection',
              ].map(
                (item) => (
                  <div
                    key={item}
                    className="bg-[#191f2f] border border-[#232a3a] rounded-xl p-3 text-xs text-[#cbc3d7]"
                  >
                    {item}
                  </div>
                )
              )}

            </div>

          </section>

        )}

      {/* LOADING */}

      {isAnalyzing && (

        <section className="rounded-2xl bg-[#141b2b] border border-[#232a3a] min-h-[380px] flex flex-col items-center justify-center text-center p-8">

          <div className="w-16 h-16 rounded-full border-4 border-purple-500/20 border-t-purple-500 animate-spin mb-5" />

          <h2 className="text-xl font-bold text-white">
            Analyzing Website
          </h2>

          <p className="text-sm text-[#958ea0] mt-3">
            Connecting to PhishGuard AI detection engine...
          </p>

        </section>

      )}

      {/* RESULTS */}

      {analysis &&
        !isAnalyzing && (

          <>

            {/* VERDICT */}

            <section
              className={`rounded-xl border p-5 ${getVerdictBackground()}`}
            >

              <div className="flex items-start gap-4">

                <div
                  className={`w-12 h-12 rounded-xl bg-[#070e1d] flex items-center justify-center ${getVerdictColor()}`}
                >

                  <span className="material-symbols-outlined text-[28px]">

                    {analysis.verdict ===
                      'malicious'
                      ? 'gpp_maybe'
                      : analysis.verdict ===
                        'suspicious'
                        ? 'warning'
                        : 'verified'}

                  </span>

                </div>

                <div>

                  <span
                    className={`text-[10px] font-bold uppercase tracking-wider ${getVerdictColor()}`}
                  >
                    {analysis.verdictLabel}
                  </span>

                  <h2 className="text-lg font-bold text-white mt-1">
                    {analysis.threatBannerTitle}
                  </h2>

                  <p className="text-sm text-[#cbc3d7] mt-2">
                    {analysis.threatBannerDesc}
                  </p>

                </div>

              </div>

            </section>

            {/* RISK SCORE */}

            <section className="bg-[#191f2f] rounded-2xl p-5 border border-[#232a3a]">

              <div className="flex items-center justify-between mb-4">

                <div>

                  <h2 className="text-base font-bold text-white">
                    Risk Score
                  </h2>

                  <p className="text-xs text-[#958ea0] mt-1">
                    Multi-layer threat assessment
                  </p>

                </div>

                <span
                  className={`text-xs font-bold uppercase ${getVerdictColor()}`}
                >
                  {analysis.verdictLabel}
                </span>

              </div>

              <div className="flex flex-col items-center">

                <div className="relative w-48 h-48">

                  <svg
                    className="w-full h-full -rotate-90"
                    viewBox="0 0 120 120"
                  >

                    <circle
                      cx="60"
                      cy="60"
                      r="50"
                      fill="transparent"
                      stroke="#232a3a"
                      strokeWidth="9"
                    />

                    <circle
                      cx="60"
                      cy="60"
                      r="50"
                      fill="transparent"
                      stroke="currentColor"
                      strokeWidth="9"
                      strokeLinecap="round"
                      strokeDasharray={
                        circumference
                      }
                      strokeDashoffset={
                        strokeOffset
                      }
                      className={
                        getVerdictColor()
                      }
                    />

                  </svg>

                  <div className="absolute inset-0 flex flex-col items-center justify-center">

                    <span
                      className={`text-4xl font-bold ${getVerdictColor()}`}
                    >
                      {analysis.score}
                    </span>

                    <span className="text-[10px] text-[#958ea0] uppercase">
                      Out of 100
                    </span>

                  </div>

                </div>

                <p className="text-sm text-[#cbc3d7] mt-3">
                  ML phishing probability:{' '}
                  {analysis.backend
                    ?.phishing_probability ??
                    'N/A'}%
                </p>

              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-6">

                <div className="bg-[#141b2b] border border-[#232a3a] rounded-xl p-3 text-center">

                  <p className="text-[10px] uppercase text-[#958ea0]">
                    Domain
                  </p>

                  <p className="text-sm font-bold text-white mt-1 break-all">
                    {analysis.backend
                      ?.domain_info
                      ?.registrable_domain ||
                      'Unknown'}
                  </p>

                  <p className="text-[10px] text-[#4fdbc8]">
                    {analysis.backend
                      ?.domain_reputation ||
                      'unknown'}
                  </p>

                </div>

                <div className="bg-[#141b2b] border border-[#232a3a] rounded-xl p-3 text-center">

                  <p className="text-[10px] uppercase text-[#958ea0]">
                    Backend Risk
                  </p>

                  <p className="text-sm font-bold text-white mt-1">
                    {analysis.score}/100
                  </p>

                  <p className="text-[10px] text-[#4fdbc8]">
                    Multi-layer score
                  </p>

                </div>

                <div className="bg-[#141b2b] border border-[#232a3a] rounded-xl p-3 text-center">

                  <p className="text-[10px] uppercase text-[#958ea0]">
                    DNS
                  </p>

                  <p className="text-sm font-bold text-white mt-1">
                    {analysis.backend
                      ?.domain_info
                      ?.dns_resolved
                      ? 'Resolved'
                      : 'Not Resolved'}
                  </p>

                  <p className="text-[10px] text-[#4fdbc8]">
                    Domain intelligence
                  </p>

                </div>

              </div>

            </section>

           {/* DETECTION REASONS */}

<section>

  <div className="flex items-center justify-between mb-4">

    <div>

      <h2 className="text-base font-bold text-white">
        Security Analysis
      </h2>

      <p className="text-xs text-[#958ea0]">
        Evidence and threat indicators identified during analysis
      </p>

    </div>

    <span className="text-xs text-[#958ea0]">
      {analysis.backend?.reasons?.length ??
        analysis.findings.length}{' '}
      signals
    </span>

  </div>


  {/* SECURITY EVIDENCE */}

  {(() => {

    const allReasons: string[] =
      analysis.backend?.reasons?.length
        ? analysis.backend.reasons
        : analysis.findings.map(
            (finding) =>
              `${finding.title}: ${finding.description}`
          );

    const positiveKeywords = [
      'low phishing probability',
      'trusted domain',
      'https is enabled',
      'tld is commonly used',
      'no phishing-related keywords',
      'tls certificate is valid',
      'certificate is valid',
      'matches the hostname',
    ];

    const securityEvidence =
      allReasons.filter((reason) =>
        positiveKeywords.some(
          (keyword) =>
            reason.toLowerCase().includes(
              keyword
            )
        )
      );

    const threatIndicators =
      allReasons.filter(
        (reason) =>
          !positiveKeywords.some(
            (keyword) =>
              reason.toLowerCase().includes(
                keyword
              )
          )
      );


    return (
      <div className="space-y-6">


        {/* POSITIVE SECURITY EVIDENCE */}

        {securityEvidence.length > 0 && (

          <div>

            <div className="flex items-center gap-2 mb-3">

              <div className="w-7 h-7 rounded-lg bg-teal-500/10 border border-teal-500/20 flex items-center justify-center">

                <span className="material-symbols-outlined text-[17px] text-[#4fdbc8]">
                  verified
                </span>

              </div>

              <div>

                <h3 className="text-sm font-bold text-white">
                  Security Evidence
                </h3>

                <p className="text-[10px] text-[#958ea0]">
                  Positive indicators identified by the analysis engine
                </p>

              </div>

            </div>


            <div className="space-y-3">

              {securityEvidence.map(
                (
                  reason,
                  index
                ) => (

                  <div
                    key={`evidence-${index}`}
                    className="flex gap-4 p-4 rounded-xl bg-teal-950/20 border border-teal-500/20"
                  >

                    <div className="w-10 h-10 shrink-0 rounded-xl flex items-center justify-center bg-teal-500/15 text-[#4fdbc8]">

                      <span className="material-symbols-outlined">
                        check_circle
                      </span>

                    </div>


                    <div className="flex-1">

                      <h4 className="text-sm font-semibold text-white">
                        Verified Security Signal
                      </h4>

                      <p className="text-xs text-[#cbc3d7] mt-2">
                        {reason}
                      </p>

                    </div>

                  </div>

                )
              )}

            </div>

          </div>

        )}


        {/* THREAT INDICATORS */}

        {threatIndicators.length > 0 && (

          <div>

            <div className="flex items-center gap-2 mb-3">

              <div className="w-7 h-7 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center justify-center">

                <span className="material-symbols-outlined text-[17px] text-red-400">
                  shield
                </span>

              </div>

              <div>

                <h3 className="text-sm font-bold text-white">
                  Threat Indicators
                </h3>

                <p className="text-[10px] text-[#958ea0]">
                  Suspicious characteristics identified during analysis
                </p>

              </div>

            </div>


            <div className="space-y-3">

              {threatIndicators.map(
                (
                  reason,
                  index
                ) => {

                  const lower =
                    reason.toLowerCase();

                  const isHighRisk =
                    lower.includes(
                      'phishing'
                    ) ||
                    lower.includes(
                      'impersonation'
                    ) ||
                    lower.includes(
                      'malicious'
                    ) ||
                    lower.includes(
                      'suspicious'
                    ) ||
                    lower.includes(
                      '@'
                    );

                  return (

                    <div
                      key={`threat-${index}`}
                      className={`flex gap-4 p-4 rounded-xl border ${
                        isHighRisk
                          ? 'bg-red-950/20 border-red-500/20'
                          : 'bg-orange-950/20 border-orange-500/20'
                      }`}
                    >

                      <div
                        className={`w-10 h-10 shrink-0 rounded-xl flex items-center justify-center ${
                          isHighRisk
                            ? 'bg-red-500/15 text-red-400'
                            : 'bg-orange-500/15 text-orange-400'
                        }`}
                      >

                        <span className="material-symbols-outlined">
                          {isHighRisk
                            ? 'gpp_maybe'
                            : 'warning'}
                        </span>

                      </div>


                      <div className="flex-1">

                        <h4 className="text-sm font-semibold text-white">
                          Threat Indicator
                        </h4>

                        <p className="text-xs text-[#cbc3d7] mt-2">
                          {reason}
                        </p>

                      </div>

                    </div>

                  );

                }
              )}

            </div>

          </div>

        )}


      </div>
    );

  })()}

</section>

            {/* URL FEATURE ANALYSIS */}

            <section>

              <div className="mb-4">

                <h2 className="text-base font-bold text-white">
                  URL Feature Analysis
                </h2>

                <p className="text-xs text-[#958ea0]">
                  Technical characteristics detected from the URL
                </p>

              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">

                {analysis.features.map(
                  (feature) => (
                    <div
                      key={
                        feature.id
                      }
                      className="p-4 rounded-xl bg-[#141b2b] border border-[#232a3a]"
                    >

                      <div className="flex items-center justify-between gap-3">

                        <span className="text-xs text-[#958ea0]">
                          {feature.label}
                        </span>

                        <span className="text-[10px] text-[#4fdbc8]">
                          {feature.tag}
                        </span>

                      </div>

                      <p className="text-sm font-semibold text-white mt-2">
                        {feature.value}
                      </p>

                      <p className="text-xs text-[#958ea0] mt-1">
                        {feature.description}
                      </p>

                    </div>
                  )
                )}

              </div>

            </section>

            {/* SSL SECURITY */}

            <section className="bg-[#191f2f] rounded-2xl p-5 border border-[#232a3a] space-y-6">

              <div>

                <h2 className="text-base font-bold text-white">
                  SSL Security Check
                </h2>

                <p className="text-xs text-[#958ea0] mt-1">
                  Real TLS certificate inspection from the backend
                </p>

              </div>

              <div className="p-4 rounded-xl bg-[#141b2b] border border-[#232a3a]">

                <div className="flex items-center gap-3">

                  <div className="w-10 h-10 rounded-xl bg-teal-500/10 text-teal-400 flex items-center justify-center">

                    <span className="material-symbols-outlined">
                      lock
                    </span>

                  </div>

                  <div>

                    <h3 className="text-sm font-semibold text-white">
                      {analysis.tlsState.title}
                    </h3>

                    <p className="text-xs text-[#4fdbc8]">
                      {analysis.tlsState.trustStatus}
                    </p>

                  </div>

                </div>

                <p className="text-xs text-[#cbc3d7] mt-4">
                  {analysis.tlsState.description}
                </p>

              </div>

              {/* REAL CERTIFICATE DETAILS */}

              {analysis.backend
                ?.ssl_analysis && (

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">

                    <div className="p-3 rounded-xl bg-[#141b2b] border border-[#232a3a]">

                      <p className="text-[10px] uppercase text-[#958ea0]">
                        Certificate Subject
                      </p>

                      <p className="text-xs text-white mt-1 break-all">
                        {analysis.backend
                          .ssl_analysis
                          .subject ||
                          'N/A'}
                      </p>

                    </div>

                    <div className="p-3 rounded-xl bg-[#141b2b] border border-[#232a3a]">

                      <p className="text-[10px] uppercase text-[#958ea0]">
                        Certificate Issuer
                      </p>

                      <p className="text-xs text-white mt-1 break-all">
                        {analysis.backend
                          .ssl_analysis
                          .issuer ||
                          'N/A'}
                      </p>

                    </div>

                    <div className="p-3 rounded-xl bg-[#141b2b] border border-[#232a3a]">

                      <p className="text-[10px] uppercase text-[#958ea0]">
                        Hostname Match
                      </p>

                      <p className="text-xs font-semibold text-white mt-1">
                        {analysis.backend
                          .ssl_analysis
                          .hostname_match
                          ? 'Yes'
                          : 'No'}
                      </p>

                    </div>

                    <div className="p-3 rounded-xl bg-[#141b2b] border border-[#232a3a]">

                      <p className="text-[10px] uppercase text-[#958ea0]">
                        Days Until Expiry
                      </p>

                      <p className="text-xs font-semibold text-white mt-1">
                        {analysis.backend
                          .ssl_analysis
                          .days_until_expiry ??
                          'N/A'}
                      </p>

                    </div>

                  </div>
                )}

              {/* BRAND DETECTION */}

              <div>

                <h2 className="text-base font-bold text-white">
                  Brand Impersonation Detection
                </h2>

                <p className="text-xs text-[#958ea0] mt-1">
                  Backend brand impersonation and trusted-domain analysis
                </p>

              </div>

              <div className="flex items-center justify-between gap-4 p-4 rounded-xl bg-[#141b2b] border border-[#232a3a]">

                <div>

                  <p className="text-sm font-semibold text-white">
                    {analysis.targetBrand ||
                      'No brand impersonation detected'}
                  </p>

                  <p className="text-xs text-[#958ea0] mt-1">
                    {analysis.backend
                      ?.domain_info
                      ?.registrable_domain ||
                      'Unknown domain'}
                  </p>

                </div>

                <div className="text-right">

                  <p
                    className={`text-sm font-bold ${getVerdictColor()}`}
                  >
                    {analysis.similarity}
                  </p>

                  <p className="text-[10px] text-[#958ea0]">
                    Brand assessment
                  </p>

                </div>

              </div>

              {/* ACTIONS */}

              <div className="flex flex-col sm:flex-row gap-3 pt-2">

                <button
                  type="button"
                  onClick={
                    handleQuarantine
                  }
                  className={`flex-1 h-11 rounded-xl font-bold text-sm flex items-center justify-center gap-2 transition-colors ${quarantined
                      ? 'bg-teal-500 text-[#062b28]'
                      : 'bg-red-600 hover:bg-red-500 text-white'
                    }`}
                >

                  <span className="material-symbols-outlined">

                    {quarantined
                      ? 'check_circle'
                      : 'block'}

                  </span>

                  {quarantined
                    ? 'Domain Quarantined'
                    : 'Quarantine Domain'}

                </button>

                <button
                  type="button"
                  onClick={
                    handleExportReport
                  }
                  className="flex-1 h-11 rounded-xl bg-[#232a3a] hover:bg-[#323949] text-white border border-[#323949] font-bold text-sm flex items-center justify-center gap-2 transition-colors"
                >

                  <span className="material-symbols-outlined">
                    picture_as_pdf
                  </span>

                  Download PDF Report

                </button>

              </div>

            </section>

          </>
        )}

    </div>
  );
}
