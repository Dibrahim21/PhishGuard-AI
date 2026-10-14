/**
 * PhishGuard AI - Centralized API Configuration
 *
 * API endpoints for all frontend features:
 * - URL Scanner (/api/scan)
 * - AI Chatbot (/api/chat)
 * - Health check (/api/health)
 *
 * VITE_API_BASE_URL must be set in Vercel environment variables to:
 *   https://phishguard-ai-backend-f18o.onrender.com
 *
 * In development it defaults to the local Flask server.
 */

const API_BASE_URL: string =
  (import.meta.env.VITE_API_BASE_URL as string) ||
  (import.meta.env.DEV
    ? 'http://127.0.0.1:5000'
    : 'https://phishguard-ai-backend-f18o.onrender.com');

export { API_BASE_URL };

export const API_ENDPOINTS = {
  /** GET /api/health — returns { status: "success" } */
  health: `${API_BASE_URL}/api/health`,
  scan:   `${API_BASE_URL}/api/scan`,
  chat:   `${API_BASE_URL}/api/chat`,
  history: `${API_BASE_URL}/api/history`,
  // Auth endpoints kept so existing imports don't break — not actively called
  register:       `${API_BASE_URL}/api/register`,
  login:          `${API_BASE_URL}/api/login`,
  me:             `${API_BASE_URL}/api/me`,
  logout:         `${API_BASE_URL}/api/logout`,
  changePassword: `${API_BASE_URL}/api/change-password`,
} as const;

export const AUTH_TOKEN_KEY = 'phishguard_token';
export const AUTH_USER_KEY  = 'phishguard_user';

export function getAuthToken(): string {
  try {
    return localStorage.getItem(AUTH_TOKEN_KEY) || '';
  } catch {
    return '';
  }
}

export function getAuthHeaders(
  includeContentType: boolean = false
): Record<string, string> {
  const token = getAuthToken();
  const headers: Record<string, string> = {};

  if (includeContentType) {
    headers['Content-Type'] = 'application/json';
  }

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  return headers;
}

export function clearStoredAuth(): void {
  try {
    localStorage.removeItem(AUTH_TOKEN_KEY);
    localStorage.removeItem(AUTH_USER_KEY);
  } catch {
    // Ignore storage exceptions
  }
}
