/**
 * PhishGuard AI - Centralized API Configuration
 *
 * Local backend URL and API endpoints for all frontend features:
 * - Authentication (/api/register, /api/login, /api/me, /api/logout, /api/change-password)
 * - URL Scanner (/api/scan)
 * - Telemetry History (/api/history)
 * - AI Chatbot (/api/chat)
 */

export const API_BASE_URL: string =
  (import.meta.env.VITE_API_BASE_URL as string) || 'http://127.0.0.1:5000';

export const API_ENDPOINTS = {
  health: `${API_BASE_URL}/`,
  register: `${API_BASE_URL}/api/register`,
  login: `${API_BASE_URL}/api/login`,
  me: `${API_BASE_URL}/api/me`,
  logout: `${API_BASE_URL}/api/logout`,
  changePassword: `${API_BASE_URL}/api/change-password`,
  scan: `${API_BASE_URL}/api/scan`,
  history: `${API_BASE_URL}/api/history`,
  chat: `${API_BASE_URL}/api/chat`,
} as const;

export const AUTH_TOKEN_KEY = 'phishguard_token';
export const AUTH_USER_KEY = 'phishguard_user';

export function getAuthToken(): string {
  try {
    return localStorage.getItem(AUTH_TOKEN_KEY) || '';
  } catch {
    return '';
  }
}

export function getAuthHeaders(includeContentType: boolean = false): Record<string, string> {
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
