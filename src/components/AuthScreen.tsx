import { FormEvent, useState } from 'react';

interface AuthScreenProps {
  onLogin: (token: string, user: { id: number; email: string }) => void;
}

const API_BASE = 'https://phishguard-ai-85s9.onrender.com';

export default function AuthScreen({
  onLogin,
}: AuthScreenProps) {
  const [mode, setMode] = useState<'login' | 'register'>('login');

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (
    event: FormEvent<HTMLFormElement>
  ) => {
    event.preventDefault();

    setError('');

    const cleanEmail = email.trim().toLowerCase();

    if (!cleanEmail || !password) {
      setError('Email and password are required.');
      return;
    }

    if (mode === 'register' && password.length < 6) {
      setError('Password must be at least 6 characters.');
      return;
    }

    setLoading(true);

    try {
      const endpoint =
        mode === 'login'
          ? '/api/login'
          : '/api/register';

      const response = await fetch(
        `${API_BASE}${endpoint}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            email: cleanEmail,
            password,
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data?.message ||
            'Authentication failed.'
        );
      }

      /*
       * REGISTER
       *
       * Backend registration creates the account.
       * Then we switch to Login so the user can
       * authenticate and receive a session token.
       */
      if (mode === 'register') {
        setMode('login');
        setPassword('');
        setError(
          'Account created successfully. Please login.'
        );
        return;
      }

      /*
       * LOGIN
       */
      if (!data?.token) {
        throw new Error(
          'Login succeeded but no session token was returned.'
        );
      }

      localStorage.setItem(
        'phishguard_token',
        data.token
      );

      if (data.user) {
        localStorage.setItem(
          'phishguard_user',
          JSON.stringify(data.user)
        );
      }

      onLogin(
        data.token,
        data.user
      );

    } catch (err) {
      console.error(
        'Authentication error:',
        err
      );

      setError(
        err instanceof Error
          ? err.message
          : 'Unable to connect to PhishGuard backend.'
      );

    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0e1117] text-white flex items-center justify-center px-4">

      <div className="w-full max-w-md">

        {/* BRAND */}
        <div className="text-center mb-8">

          <div className="mx-auto w-16 h-16 rounded-2xl bg-gradient-to-br from-purple-600/20 to-teal-500/20 border border-purple-500/20 flex items-center justify-center mb-4">

            <span className="material-symbols-outlined text-4xl text-[#4fdbc8]">
              shield
            </span>

          </div>

          <h1 className="text-2xl font-bold">
            PHISHGUARD AI
          </h1>

          <p className="text-sm text-[#958ea0] mt-2">
            Intelligent Phishing Website Detection System
          </p>

        </div>

        {/* CARD */}
        <div className="bg-[#141b2b] border border-[#232a3a] rounded-2xl p-6 shadow-2xl">

          {/* TABS */}
          <div className="grid grid-cols-2 bg-[#0e1117] rounded-xl p-1 mb-6">

            <button
              type="button"
              onClick={() => {
                setMode('login');
                setError('');
              }}
              className={`py-2.5 rounded-lg text-sm font-semibold transition ${
                mode === 'login'
                  ? 'bg-[#232a3a] text-white'
                  : 'text-[#958ea0] hover:text-white'
              }`}
            >
              Login
            </button>

            <button
              type="button"
              onClick={() => {
                setMode('register');
                setError('');
              }}
              className={`py-2.5 rounded-lg text-sm font-semibold transition ${
                mode === 'register'
                  ? 'bg-[#232a3a] text-white'
                  : 'text-[#958ea0] hover:text-white'
              }`}
            >
              Register
            </button>

          </div>

          {/* TITLE */}
          <div className="mb-5">

            <h2 className="text-lg font-bold">
              {mode === 'login'
                ? 'Welcome back'
                : 'Create your account'}
            </h2>

            <p className="text-xs text-[#958ea0] mt-1">
              {mode === 'login'
                ? 'Sign in to access your security dashboard.'
                : 'Create an account to keep your scans private.'}
            </p>

          </div>

          {/* FORM */}
          <form
            onSubmit={handleSubmit}
            className="space-y-4"
          >

            {/* EMAIL */}
            <div>

              <label className="block text-xs font-semibold text-[#cbc3d7] mb-2">
                Email
              </label>

              <input
                type="email"
                value={email}
                onChange={(event) =>
                  setEmail(event.target.value)
                }
                placeholder="you@example.com"
                autoComplete="email"
                className="w-full bg-[#0e1117] border border-[#232a3a] rounded-xl px-4 py-3 text-sm text-white placeholder:text-[#625d6a] focus:outline-none focus:border-purple-500 transition"
              />

            </div>

            {/* PASSWORD */}
            <div>

              <label className="block text-xs font-semibold text-[#cbc3d7] mb-2">
                Password
              </label>

              <input
                type="password"
                value={password}
                onChange={(event) =>
                  setPassword(event.target.value)
                }
                placeholder="••••••••"
                autoComplete={
                  mode === 'login'
                    ? 'current-password'
                    : 'new-password'
                }
                className="w-full bg-[#0e1117] border border-[#232a3a] rounded-xl px-4 py-3 text-sm text-white placeholder:text-[#625d6a] focus:outline-none focus:border-purple-500 transition"
              />

            </div>

            {/* ERROR / SUCCESS */}
            {error && (
              <div
                className={`rounded-xl px-4 py-3 text-xs border ${
                  error.includes(
                    'successfully'
                  )
                    ? 'bg-teal-500/10 border-teal-500/20 text-teal-300'
                    : 'bg-red-500/10 border-red-500/20 text-red-300'
                }`}
              >
                {error}
              </div>
            )}

            {/* SUBMIT */}
            <button
              type="submit"
              disabled={loading}
              className="w-full h-11 rounded-xl bg-gradient-to-r from-[#7c3aed] to-[#14b8a6] text-white font-bold text-sm hover:brightness-110 transition disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading
                ? 'Please wait...'
                : mode === 'login'
                  ? 'Login to PhishGuard'
                  : 'Create Account'}
            </button>

          </form>

        </div>

        <p className="text-center text-[10px] text-[#625d6a] mt-5">
          PhishGuard AI • Secure Security Analysis
        </p>

      </div>

    </div>
  );
}
