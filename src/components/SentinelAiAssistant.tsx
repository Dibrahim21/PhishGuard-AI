import { useEffect, useRef, useState } from 'react';
import {
  Bot,
  Mic,
  Volume2,
  VolumeX,
  Send,
  ShieldCheck,
  Sparkles,
  User,
  Loader2,
  Brain,
  Search,
  Radio,
} from 'lucide-react';

interface SentinelAiAssistantProps {
  onShowToast: (msg: string, isAlert?: boolean) => void;
  onInspectUrl: (url: string) => void;
}

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  text: string;
  timestamp: string;
}

const API_BASE = 'https://phishguard-ai-85s9.onrender.com';

const getAuthHeaders = (): Record<string, string> => {
  const token = localStorage.getItem('phishguard_token') || '';

  return token
    ? { Authorization: `Bearer ${token}` }
    : {};
};

const initialMessages: ChatMessage[] = [
  {
    id: 'sentinel-init',
    role: 'assistant',
    timestamp: new Date().toLocaleTimeString('en-GB', { hour12: false }) + ' UTC',
    text:
      'Sentinel AI is online. Ask me about phishing, URLs, SSL/TLS, RDAP, DNS, brand impersonation, or your latest PhishGuard scan.',
  },
];

function looksLikeUrl(text: string): boolean {
  return /(https?:\/\/|www\.)[^\s]+/i.test(text);
}

function extractUrl(text: string): string | null {
  const match = text.match(/https?:\/\/[^\s]+|www\.[^\s]+/i);
  return match?.[0]?.replace(/[),.!?]+$/, '') || null;
}

export default function SentinelAiAssistant({
  onShowToast,
  onInspectUrl,
}: SentinelAiAssistantProps) {
  const [messages, setMessages] = useState<ChatMessage[]>(initialMessages);
  const [inputValue, setInputValue] = useState('');
  const [audioFeedback, setAudioFeedback] = useState(true);
  const [isThinking, setIsThinking] = useState(false);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isThinking]);

  const getTimestamp = () =>
    new Date().toLocaleTimeString('en-GB', { hour12: false }) + ' UTC';

  const speakText = (text: string) => {
    if (
      !audioFeedback ||
      typeof window === 'undefined' ||
      !('speechSynthesis' in window)
    ) {
      return;
    }

    window.speechSynthesis.cancel();
    const utterance = new SpeechSynthesisUtterance(text.slice(0, 500));
    utterance.rate = 1;
    utterance.pitch = 1;
    window.speechSynthesis.speak(utterance);
  };

  const askBackend = async (query: string, scanContext?: unknown) => {
    const history = messages
      .slice(-10)
      .map((msg) => ({
        role: msg.role,
        content: msg.text,
      }));

    const response = await fetch(`${API_BASE}/api/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...getAuthHeaders(),
      },
      body: JSON.stringify({
        message: query,
        history,
        scan_context: scanContext || null,
      }),
    });

    const data = await response.json();

    if (!response.ok || data.status !== 'success') {
      throw new Error(
        data.message || 'AI assistant request failed.'
      );
    }

    return String(data.reply || '');
  };

  const handleSendMessage = async (textToSend?: string) => {
    const query = (textToSend ?? inputValue).trim();

    if (!query || isThinking) return;

    const userMessage: ChatMessage = {
      id: `user-${Date.now()}`,
      role: 'user',
      timestamp: getTimestamp(),
      text: query,
    };

    setMessages((prev) => [...prev, userMessage]);
    setInputValue('');
    setIsThinking(true);

    try {
      let scanContext: unknown = undefined;

      // If a URL is pasted, run the real PhishGuard scanner first.
      // The AI then explains the actual backend result.
      if (looksLikeUrl(query)) {
        const detectedUrl = extractUrl(query);

        if (detectedUrl) {
          const normalizedUrl = detectedUrl.startsWith('http')
            ? detectedUrl
            : `https://${detectedUrl}`;

          const scanResponse = await fetch(`${API_BASE}/api/scan`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              ...getAuthHeaders(),
            },
            body: JSON.stringify({ url: normalizedUrl }),
          });

          const scanData = await scanResponse.json();

          if (scanResponse.ok && scanData.status === 'success') {
            scanContext = scanData;
            onInspectUrl(normalizedUrl);
          }
        }
      }

      const reply = await askBackend(query, scanContext);

      const assistantMessage: ChatMessage = {
        id: `assistant-${Date.now()}`,
        role: 'assistant',
        timestamp: getTimestamp(),
        text: reply,
      };

      setMessages((prev) => [...prev, assistantMessage]);
      speakText(reply);
    } catch (error: any) {
      const message =
        error?.message ||
        'Unable to reach the AI backend.';

      setMessages((prev) => [
        ...prev,
        {
          id: `error-${Date.now()}`,
          role: 'assistant',
          timestamp: getTimestamp(),
          text:
            `I could not complete the AI request.\n\n${message}\n\n` +
            'Make sure the Flask backend is running and your Gemini API configuration is available.',
        },
      ]);

      onShowToast(message, true);
    } finally {
      setIsThinking(false);
    }
  };

  const handleVoiceInput = () => {
    const SpeechRecognition =
      (window as any).SpeechRecognition ||
      (window as any).webkitSpeechRecognition;

    if (!SpeechRecognition) {
      onShowToast(
        'Voice input is not supported by this browser.',
        true
      );
      return;
    }

    const recognition = new SpeechRecognition();
    recognition.lang = 'en-IN';
    recognition.interimResults = false;
    recognition.maxAlternatives = 1;

    recognition.onresult = (event: any) => {
      const transcript = event.results?.[0]?.[0]?.transcript || '';
      setInputValue(transcript);
    };

    recognition.onerror = () => {
      onShowToast('Voice input failed. Please try again.', true);
    };

    recognition.start();
  };

  const promptChips = [
    ['Why can a URL be phishing even with HTTPS?', ShieldCheck],
    ['Explain RDAP in simple words', Search],
    ['How does brand impersonation work?', Brain],
    ['What should I do after finding a phishing URL?', Sparkles],
  ] as const;

  return (
    <div className="w-full max-w-5xl mx-auto px-4 py-5 pb-24 space-y-5 text-[#dce2f7]">

      <section className="relative overflow-hidden rounded-2xl bg-[#141722] border border-[#242a38] p-5 shadow-xl">
        <div className="absolute right-0 top-0 w-72 h-72 bg-purple-600/10 rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="relative w-12 h-12 rounded-xl bg-purple-500/15 border border-purple-500/30 flex items-center justify-center">
              <Bot className="w-6 h-6 text-purple-300" />
              <span className="absolute bottom-0 right-0 w-3 h-3 rounded-full bg-teal-400 border-2 border-[#141722]" />
            </div>

            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-bold text-white">
                  Sentinel AI Advisor
                </h1>
                <span className="px-2 py-0.5 rounded-full bg-purple-500/15 border border-purple-500/30 text-[10px] font-mono text-purple-300">
                  REAL AI
                </span>
              </div>

              <p className="text-xs text-teal-400 mt-1 flex items-center gap-1">
                <Radio className="w-3 h-3" />
                PhishGuard Backend • Security Intelligence
              </p>
            </div>
          </div>

          <button
            onClick={() => {
              setAudioFeedback((prev) => !prev);
              onShowToast(
                audioFeedback
                  ? 'Voice feedback muted'
                  : 'Voice feedback enabled'
              );
            }}
            className="w-10 h-10 rounded-lg bg-[#0f1118] border border-[#242a38] flex items-center justify-center hover:bg-[#1a1f2c]"
          >
            {audioFeedback ? (
              <Volume2 className="w-5 h-5 text-purple-300" />
            ) : (
              <VolumeX className="w-5 h-5 text-zinc-400" />
            )}
          </button>
        </div>

        <div className="relative z-10 mt-5 rounded-xl bg-[#0f1118] border border-[#242a38] px-4 py-3">
          <div className="flex items-center gap-2 text-xs">
            <span className="w-2 h-2 rounded-full bg-teal-400 animate-pulse" />
            <span className="text-teal-400 font-bold">LIVE AI CHANNEL</span>
            <span className="text-zinc-500">
              • Backend-powered responses
            </span>
          </div>
        </div>
      </section>

      <section className="flex flex-col gap-4">
        {messages.map((msg) => (
          <div
            key={msg.id}
            className={`flex gap-3 ${
              msg.role === 'user' ? 'justify-end' : ''
            }`}
          >
            {msg.role === 'assistant' && (
              <div className="w-9 h-9 rounded-lg bg-purple-500/15 border border-purple-500/20 flex items-center justify-center shrink-0">
                <Bot className="w-5 h-5 text-purple-300" />
              </div>
            )}

            <div
              className={
                msg.role === 'user'
                  ? 'max-w-[85%] bg-purple-400 text-purple-950 rounded-2xl rounded-tr-sm p-4 shadow-lg'
                  : 'max-w-[90%] rounded-2xl rounded-tl-sm bg-[#141722] border border-[#242a38] p-4'
              }
            >
              <div className="flex justify-between gap-5 mb-2">
                <span
                  className={`text-[10px] font-bold ${
                    msg.role === 'user'
                      ? ''
                      : 'text-purple-300'
                  }`}
                >
                  {msg.role === 'user' ? 'ANALYST (YOU)' : 'SENTINEL AI'}
                </span>

                <span
                  className={`text-[10px] font-mono ${
                    msg.role === 'user'
                      ? 'opacity-60'
                      : 'text-zinc-500'
                  }`}
                >
                  {msg.timestamp}
                </span>
              </div>

              <p
                className={`text-sm leading-relaxed whitespace-pre-line ${
                  msg.role === 'user'
                    ? 'font-medium'
                    : 'text-zinc-300'
                }`}
              >
                {msg.text}
              </p>
            </div>

            {msg.role === 'user' && (
              <div className="w-9 h-9 rounded-lg bg-[#1a1f2c] flex items-center justify-center shrink-0">
                <User className="w-5 h-5 text-teal-400" />
              </div>
            )}
          </div>
        ))}

        {isThinking && (
          <div className="flex gap-3">
            <div className="w-9 h-9 rounded-lg bg-purple-500/15 flex items-center justify-center">
              <Loader2 className="w-5 h-5 text-purple-300 animate-spin" />
            </div>

            <div className="bg-[#141722] border border-[#242a38] rounded-2xl rounded-tl-sm px-4 py-3 flex items-center gap-2 text-xs text-zinc-400">
              <span className="w-2 h-2 bg-purple-400 rounded-full animate-ping" />
              Sentinel is analyzing...
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </section>

      <section>
        <p className="text-[10px] uppercase tracking-wider font-mono text-zinc-500 mb-2">
          Security Prompts
        </p>

        <div className="flex gap-2 overflow-x-auto pb-2">
          {promptChips.map(([label, Icon]) => (
            <button
              key={label}
              onClick={() => handleSendMessage(label)}
              disabled={isThinking}
              className="shrink-0 flex items-center gap-2 px-3 py-2 rounded-full bg-[#141722] hover:bg-[#1a1f2c] border border-[#242a38] text-xs text-zinc-300 hover:text-purple-300 disabled:opacity-40"
            >
              <Icon className="w-4 h-4 text-purple-300" />
              {label}
            </button>
          ))}
        </div>
      </section>

      <section className="sticky bottom-4 z-30 flex items-center gap-2 bg-[#141722] border border-[#30394c] rounded-2xl p-2 shadow-2xl">
        <button
          onClick={handleVoiceInput}
          className="w-11 h-11 rounded-xl bg-[#0f1118] border border-[#242a38] flex items-center justify-center text-purple-300 hover:text-teal-400"
          title="Voice input"
        >
          <Mic className="w-5 h-5" />
        </button>

        <input
          type="text"
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              handleSendMessage();
            }
          }}
          placeholder="Ask Sentinel AI or paste a suspicious URL..."
          className="flex-1 h-11 bg-[#0f1118] border border-[#242a38] rounded-xl px-4 text-sm text-white placeholder:text-zinc-500 focus:outline-none focus:border-purple-500"
        />

        <button
          onClick={() => handleSendMessage()}
          disabled={!inputValue.trim() || isThinking}
          className="w-11 h-11 rounded-xl bg-purple-500 hover:bg-purple-400 disabled:opacity-40 text-white flex items-center justify-center transition-all active:scale-95"
        >
          <Send className="w-5 h-5" />
        </button>
      </section>
    </div>
  );
}

