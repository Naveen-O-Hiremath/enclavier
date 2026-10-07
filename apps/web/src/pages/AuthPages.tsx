import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { AlertTriangle, Building2, Fingerprint, KeyRound, Laptop, LifeBuoy, Lock, LogOut, ShieldCheck, Smartphone } from 'lucide-react';
import { formatRecoveryCode, OtpInput } from '../components/OtpInput';
import { ApiError } from '../lib/api';
import { forgetServerInfo, useServerInfo } from '../lib/serverInfo';
import type { TwoFactorChallenge, TwoFactorMethod } from '@enclavier/shared';
import { assertSecurityKey } from '../lib/security';
import { loadPendingInvite } from '../lib/orgs';
import { InvalidPasswordError } from '@enclavier/crypto';
import { useSession } from '../lib/session';
import { Logo, PasswordInput, Spinner, StrengthMeter } from '../components/ui';
import { errorMessage } from '../components/Toast';

export function AuthShell({ title, subtitle, children, footer }: { title: string; subtitle: string; children: ReactNode; footer?: ReactNode }) {
  return (
    <div className="flex min-h-full items-center justify-center bg-gradient-to-b from-brand-50 to-slate-50 px-4 py-12 dark:from-slate-900 dark:to-slate-950">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex justify-center">
          <Logo size="lg" />
        </div>
        <div className="card p-6 shadow-lg">
          <h1 className="text-lg font-semibold">{title}</h1>
          <p className="mt-1 mb-5 text-sm text-slate-500">{subtitle}</p>
          {children}
        </div>
        {footer && <div className="mt-6 text-center text-sm text-slate-500">{footer}</div>}
        <p className="mt-6 text-center text-xs text-slate-400">
          End-to-end encrypted. Your master password never leaves this device.
        </p>
      </div>
    </div>
  );
}

function InviteBanner() {
  const invite = loadPendingInvite();
  if (!invite) return null;
  return (
    <div className="mb-4 flex items-start gap-2 rounded-lg bg-brand-50 px-3 py-2 text-sm text-brand-700 dark:bg-brand-500/10 dark:text-brand-400">
      <Building2 className="mt-0.5 h-4 w-4 shrink-0" />
      You have a pending organization invitation for {invite.email}. Continue to accept it.
    </div>
  );
}

export function FormError({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <div className="mb-4 flex items-start gap-2 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700 dark:bg-red-950/50 dark:text-red-300">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
      {message}
    </div>
  );
}

const METHOD: Record<TwoFactorMethod, { icon: typeof KeyRound; title: string; hint: string; switchTo: string }> = {
  totp: {
    icon: Smartphone,
    title: 'Enter your verification code',
    hint: 'Open your authenticator app and type the 6-digit code for Enclavier.',
    switchTo: 'Use an authenticator app',
  },
  webauthn: {
    icon: Fingerprint,
    title: 'Use your security key',
    hint: "Insert your security key, or use your device's passkey, then follow your browser's prompt.",
    switchTo: 'Use a security key or passkey',
  },
  recovery: {
    icon: LifeBuoy,
    title: 'Enter a recovery code',
    hint: 'Use one of the codes you saved when you turned on two-step login. Each code works once.',
    switchTo: 'Use a recovery code',
  },
};

export function TwoFactorStep({ challenge, onCancel, onDone }: { challenge: TwoFactorChallenge; onCancel: () => void; onDone?: () => void }) {
  const completeTwoFactor = useSession((s) => s.completeTwoFactor);
  const initial: TwoFactorMethod = challenge.methods.includes('webauthn') ? 'webauthn' : challenge.methods.includes('totp') ? 'totp' : 'recovery';
  const [method, setMethod] = useState<TwoFactorMethod>(initial);
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run(input: Parameters<typeof completeTwoFactor>[0]) {
    setBusy(true);
    setError(null);
    try {
      await completeTwoFactor(input);
      onDone?.();
    } catch (err) {
      const msg = errorMessage(err);
      // Browsers raise NotAllowedError when the user cancels or the key times out.
      setError(/NotAllowed|timed out|cancel/i.test(msg) ? 'Security key prompt was cancelled or timed out. Try again.' : msg);
      setCode('');
      if (/expired/i.test(msg)) onCancel();
    } finally {
      setBusy(false);
    }
  }

  const useKey = async () => {
    try {
      await run({ method: 'webauthn', webauthnResponse: await assertSecurityKey(challenge.webauthnOptions) });
    } catch (err) {
      setError(errorMessage(err));
    }
  };

  const m = METHOD[method];
  const others = challenge.methods.filter((x) => x !== method);
  const recoveryReady = code.replace(/[^A-Z0-9]/gi, '').length === 10;

  return (
    <>
      <div className="mb-5 flex flex-col items-center text-center">
        <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-brand-50 text-brand-600 ring-8 ring-brand-50/50 dark:bg-brand-500/10 dark:ring-brand-500/5">
          <m.icon className="h-7 w-7" />
        </div>
        <h2 className="mt-4 text-base font-semibold">{m.title}</h2>
        <p className="mt-1 max-w-xs text-sm text-slate-500">{m.hint}</p>
      </div>

      {method === 'webauthn' && (
        <button className="btn-primary w-full py-2.5" onClick={useKey} disabled={busy} autoFocus>
          {busy ? <Spinner /> : <KeyRound className="h-4 w-4" />} {busy ? 'Waiting for your key…' : 'Continue with security key'}
        </button>
      )}

      {method === 'totp' && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (code.length === 6) void run({ method, code });
          }}
        >
          <OtpInput
            value={code}
            onChange={(v) => {
              setCode(v);
              if (error) setError(null);
            }}
            onComplete={(v) => void run({ method: 'totp', code: v })}
            disabled={busy}
            invalid={!!error}
            autoFocus
          />
          <button className="btn-primary mt-5 w-full py-2.5" disabled={busy || code.length !== 6}>
            {busy && <Spinner />} {busy ? 'Verifying…' : 'Verify'}
          </button>
        </form>
      )}

      {method === 'recovery' && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void run({ method, code });
          }}
        >
          <input
            className={`input py-3 text-center font-mono text-lg tracking-[0.25em] uppercase ${error ? 'animate-shake border-red-400' : ''}`}
            autoFocus
            autoComplete="off"
            spellCheck={false}
            placeholder="XXXXX-XXXXX"
            aria-label="Recovery code"
            value={code}
            onChange={(e) => {
              setCode(formatRecoveryCode(e.target.value));
              if (error) setError(null);
            }}
            maxLength={11}
          />
          <button className="btn-primary mt-5 w-full py-2.5" disabled={busy || !recoveryReady}>
            {busy && <Spinner />} {busy ? 'Verifying…' : 'Verify'}
          </button>
        </form>
      )}

      <div aria-live="polite" className="min-h-6 pt-3 text-center text-sm text-red-600 dark:text-red-400">
        {error && (
          <span className="inline-flex items-center gap-1.5">
            <AlertTriangle className="h-4 w-4 shrink-0" /> {error}
          </span>
        )}
      </div>

      <div className="mt-2 border-t border-slate-100 pt-4 dark:border-slate-800">
        {others.length > 0 && <p className="mb-2 text-center text-xs font-medium tracking-wide text-slate-400 uppercase">Having trouble?</p>}
        <div className="space-y-1.5">
          {others.map((o) => {
            const Icon = METHOD[o].icon;
            return (
              <button
                key={o}
                type="button"
                disabled={busy}
                className="flex w-full items-center gap-3 rounded-lg border border-slate-200 px-3 py-2 text-left text-sm text-slate-700 transition hover:border-brand-400 hover:bg-brand-50/50 dark:border-slate-800 dark:text-slate-200 dark:hover:bg-slate-800/60"
                onClick={() => {
                  setMethod(o);
                  setError(null);
                  setCode('');
                }}
              >
                <Icon className="h-4 w-4 text-slate-400" />
                {METHOD[o].switchTo}
              </button>
            );
          })}
        </div>
        <button type="button" className="mt-3 block w-full text-center text-sm text-slate-500 hover:text-slate-800 hover:underline dark:hover:text-slate-200" onClick={onCancel}>
          Back to sign in
        </button>
      </div>
    </>
  );
}

export function LoginPage() {
  const login = useSession((s) => s.login);
  const cancelTwoFactor = useSession((s) => s.cancelTwoFactor);
  const [params] = useSearchParams();
  const [email, setEmail] = useState(() => params.get('email') ?? loadPendingInvite()?.email ?? '');
  const [ssoRequired, setSsoRequired] = useState(false);
  const info = useServerInfo();
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [challenge, setChallenge] = useState<TwoFactorChallenge | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setSsoRequired(false);
    try {
      const next = await login(email.trim().toLowerCase(), password);
      if (next) {
        setPassword('');
        setChallenge(next);
      }
    } catch (err) {
      setError(errorMessage(err));
      setSsoRequired(err instanceof ApiError && err.code === 'sso_required');
    } finally {
      setBusy(false);
    }
  }

  if (challenge) {
    return (
      <AuthShell title="Two-step login" subtitle={`Signing in as ${email.trim().toLowerCase()}`}>
        <TwoFactorStep
          challenge={challenge}
          onCancel={() => {
            cancelTwoFactor();
            setChallenge(null);
          }}
        />
      </AuthShell>
    );
  }

  return (
    <AuthShell
      title="Sign in"
      subtitle="Unlock your vault with your master password."
      footer={
        info && !info.signupsEnabled ? (
          <>Accounts on this server are created by invitation or single sign-on.</>
        ) : (
          <>
            New to Enclavier?{' '}
            <Link to="/register" className="font-medium text-brand-600 hover:underline dark:text-brand-400">
              Create an account
            </Link>
          </>
        )
      }
    >
      {info?.setupRequired && (
        <div className="mb-4 rounded-lg border border-brand-100 bg-brand-50 px-3 py-3 text-sm text-brand-800 dark:border-brand-500/20 dark:bg-brand-500/10 dark:text-brand-300">
          <p className="font-medium">Welcome to your new Enclavier server</p>
          <p className="mt-0.5 text-xs">No accounts exist yet. Create the first one to get started, then set up your organization and invite the team.</p>
          <Link to="/register" className="btn-primary mt-3 w-full">Create the first account</Link>
        </div>
      )}
      <InviteBanner />
      <FormError message={error} />
      <form onSubmit={submit} className="space-y-4">
        <div>
          <label className="label" htmlFor="email">E-mail</label>
          <input id="email" className="input" type="email" autoComplete="username" required autoFocus value={email} onChange={(e) => setEmail(e.target.value)} />
        </div>
        <div>
          <label className="label" htmlFor="password">Master password</label>
          <PasswordInput id="password" value={password} onChange={setPassword} autoComplete="current-password" />
        </div>
        <button className="btn-primary w-full" disabled={busy || !email || !password}>
          {busy ? <Spinner /> : null}
          {busy ? 'Deriving keys…' : 'Sign in'}
        </button>
      </form>
      <div className="my-4 flex items-center gap-3 text-xs text-slate-400">
        <span className="h-px flex-1 bg-slate-200 dark:bg-slate-800" /> or <span className="h-px flex-1 bg-slate-200 dark:bg-slate-800" />
      </div>
      <Link to="/sso" className={`${ssoRequired ? 'btn-primary' : 'btn-secondary'} w-full`}>
        <Building2 className="h-4 w-4" /> Sign in with SSO
      </Link>
    </AuthShell>
  );
}

export function RegisterPage() {
  const register = useSession((s) => s.register);
  const [params] = useSearchParams();
  const invite = loadPendingInvite();
  const [name, setName] = useState('');
  const [email, setEmail] = useState(() => params.get('email') ?? invite?.email ?? '');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const tooShort = password.length > 0 && password.length < 12;
  const mismatch = confirm.length > 0 && confirm !== password;

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (password.length < 12) return setError('Use at least 12 characters for your master password.');
    if (password !== confirm) return setError('Passwords do not match.');
    setBusy(true);
    setError(null);
    try {
      const normalized = email.trim().toLowerCase();
      // Passing the invitation lets invited users register even when open sign-up is disabled.
      await register(normalized, name.trim(), password, invite && invite.email === normalized ? invite : undefined);
      forgetServerInfo();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell
      title="Create your vault"
      subtitle="Your master password encrypts everything. Choose a long passphrase."
      footer={
        <>
          Already have an account?{' '}
          <Link to="/" className="font-medium text-brand-600 hover:underline dark:text-brand-400">Sign in</Link>
        </>
      }
    >
      <InviteBanner />
      <FormError message={error} />
      <form onSubmit={submit} className="space-y-4">
        <div>
          <label className="label" htmlFor="name">Name</label>
          <input id="name" className="input" required autoFocus value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" />
        </div>
        <div>
          <label className="label" htmlFor="email">E-mail</label>
          <input id="email" className="input" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" />
        </div>
        <div>
          <label className="label" htmlFor="password">Master password</label>
          <PasswordInput id="password" value={password} onChange={setPassword} autoComplete="new-password" />
          <StrengthMeter password={password} />
          {tooShort && <p className="mt-1 text-xs text-amber-600">At least 12 characters.</p>}
        </div>
        <div>
          <label className="label" htmlFor="confirm">Confirm master password</label>
          <PasswordInput id="confirm" value={confirm} onChange={setConfirm} autoComplete="new-password" />
          {mismatch && <p className="mt-1 text-xs text-red-600">Passwords do not match.</p>}
        </div>
        <label className="flex items-start gap-2.5 rounded-lg bg-amber-50 p-3 text-xs text-amber-800 dark:bg-amber-950/40 dark:text-amber-200">
          <input type="checkbox" className="mt-0.5" checked={ack} onChange={(e) => setAck(e.target.checked)} />
          I understand Enclavier cannot see or reset my master password. If I forget it, my vault cannot be recovered.
        </label>
        <button className="btn-primary w-full" disabled={busy || !ack || !name || !email || !password || !confirm}>
          {busy ? <Spinner /> : null}
          {busy ? 'Generating keys…' : 'Create account'}
        </button>
      </form>
    </AuthShell>
  );
}

export function LockPage() {
  const { profile, unlock, logout, sso, isTrustedDevice, ssoStart, requestDeviceApproval, checkDeviceApproval } = useSession();
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [approval, setApproval] = useState<{ fingerprint: string; admin: boolean } | null>(null);

  // While waiting for an approval, poll for the sealed key.
  useEffect(() => {
    if (!approval) return;
    const timer = setInterval(() => {
      checkDeviceApproval().then(
        (state) => {
          if (state === 'denied') {
            setApproval(null);
            setError('The request was denied or expired.');
          }
        },
        (e) => setError(errorMessage(e)),
      );
    }, 4000);
    return () => clearInterval(timer);
  }, [approval, checkDeviceApproval]);

  async function ask(admin: boolean) {
    setError(null);
    setBusy(true);
    try {
      const { fingerprint } = await requestDeviceApproval(admin ? sso?.id : undefined);
      setApproval({ fingerprint, admin });
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  if (approval) {
    return (
      <AuthShell
        title={approval.admin ? 'Waiting for an administrator' : 'Approve on another device'}
        subtitle={
          approval.admin
            ? `An administrator of ${sso?.name ?? 'your organization'} can approve this browser.`
            : 'Open Enclavier on a device where your vault is unlocked and go to Settings → Devices.'
        }
      >
        <FormError message={error} />
        <p className="text-xs font-medium tracking-wide text-slate-500 uppercase">Fingerprint phrase</p>
        <p className="mt-1 rounded-lg bg-slate-100 px-3 py-2 text-center font-mono text-sm dark:bg-slate-800">{approval.fingerprint}</p>
        <p className="mt-2 text-xs text-slate-500">Approve only if the other screen shows exactly the same phrase.</p>
        <div className="mt-5 flex items-center justify-center gap-2 text-sm text-slate-500"><Spinner /> Waiting for approval…</div>
        <button type="button" className="btn-ghost mt-4 w-full" onClick={() => setApproval(null)}>Cancel</button>
      </AuthShell>
    );
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await unlock(password);
    } catch (err) {
      setError(err instanceof InvalidPasswordError ? 'Incorrect master password.' : errorMessage(err));
      setPassword('');
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell title="Vault locked" subtitle={`Signed in as ${profile?.email ?? ''}`}>
      <FormError message={error} />
      <form onSubmit={submit} className="space-y-4">
        <div>
          <label className="label" htmlFor="password">Master password</label>
          <PasswordInput id="password" value={password} onChange={setPassword} autoFocus autoComplete="current-password" />
        </div>
        <button className="btn-primary w-full" disabled={busy || !password}>
          {busy ? <Spinner /> : <Lock className="h-4 w-4" />}
          {busy ? 'Unlocking…' : 'Unlock'}
        </button>
        {sso && (
          <div className="space-y-2 border-t border-slate-100 pt-4 dark:border-slate-800">
            {isTrustedDevice() && (
              <button
                type="button"
                className="btn-secondary w-full"
                disabled={busy}
                onClick={() => ssoStart({ email: profile?.email ?? '', identifier: sso.identifier }).catch((e) => setError(errorMessage(e)))}
              >
                <Building2 className="h-4 w-4" /> Unlock with {sso.name} SSO
              </button>
            )}
            <button type="button" className="btn-ghost w-full" disabled={busy} onClick={() => void ask(false)}>
              <Laptop className="h-4 w-4" /> Approve from another device
            </button>
            <button type="button" className="btn-ghost w-full" disabled={busy} onClick={() => void ask(true)}>
              <ShieldCheck className="h-4 w-4" /> Ask an administrator
            </button>
          </div>
        )}
        <button type="button" className="btn-ghost w-full" onClick={() => void logout()}>
          <LogOut className="h-4 w-4" /> Log out
        </button>
      </form>
    </AuthShell>
  );
}
