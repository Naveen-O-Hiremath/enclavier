import { useEffect, useRef, useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Building2, KeyRound } from 'lucide-react';
import type { SsoDiscovery, TwoFactorChallenge } from '@enclavier/shared';
import { api } from '../lib/api';
import { useSession, type SsoOutcome } from '../lib/session';
import { PasswordInput, Spinner, StrengthMeter } from '../components/ui';
import { errorMessage } from '../components/Toast';
import { AuthShell, FormError, TwoFactorStep } from './AuthPages';

/** /sso — enter a work e-mail (verified domains) or the organization identifier. */
export function SsoStartPage() {
  const ssoStart = useSession((s) => s.ssoStart);
  const profile = useSession((s) => s.profile);
  const [email, setEmail] = useState(profile?.email ?? '');
  const [identifier, setIdentifier] = useState('');
  const [askIdentifier, setAskIdentifier] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (!identifier) {
        const found = await api<SsoDiscovery>('POST', '/api/sso/discover', { email: email.trim().toLowerCase() }, { auth: false });
        if (!found.available) {
          setAskIdentifier(true);
          setBusy(false);
          return;
        }
      }
      await ssoStart({ email, identifier }); // navigates to the identity provider
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  return (
    <AuthShell
      title="Single sign-on"
      subtitle="Sign in with your organization's identity provider."
      footer={<Link to="/" className="font-medium text-brand-600 hover:underline dark:text-brand-400">Use your master password instead</Link>}
    >
      <FormError message={error} />
      <form onSubmit={submit} className="space-y-4">
        <div>
          <label className="label" htmlFor="sso-email">Work e-mail</label>
          <input id="sso-email" className="input" type="email" required autoFocus autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} />
        </div>
        {askIdentifier && (
          <div>
            <label className="label" htmlFor="sso-id">Organization identifier</label>
            <input id="sso-id" className="input" required autoFocus value={identifier} onChange={(e) => setIdentifier(e.target.value)} placeholder="acme" />
            <p className="mt-1 text-xs text-slate-500">Your domain isn't linked to an organization. Ask your administrator for the identifier.</p>
          </div>
        )}
        <button className="btn-primary w-full" disabled={busy || !email || (askIdentifier && !identifier)}>
          {busy ? <Spinner /> : <Building2 className="h-4 w-4" />} Continue
        </button>
      </form>
    </AuthShell>
  );
}

/** /sso/callback#code=… — the identity provider sent the browser back here. */
export function SsoCallbackPage() {
  const ssoComplete = useSession((s) => s.ssoComplete);
  const cancelTwoFactor = useSession((s) => s.cancelTwoFactor);
  const navigate = useNavigate();
  const [outcome, setOutcome] = useState<SsoOutcome | null>(null);
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return; // codes are single-use: never exchange twice (StrictMode)
    started.current = true;
    const params = new URLSearchParams(window.location.hash.slice(1));
    window.history.replaceState(null, '', '/sso/callback'); // keep the code out of history
    const code = params.get('code');
    if (!code) {
      setError(params.get('error') ?? 'The sign-in did not complete.');
      return;
    }
    ssoComplete(code).then(
      (o) => (o.kind === 'unlocked' || o.kind === 'locked' ? navigate('/vault', { replace: true }) : setOutcome(o)),
      (e) => setError(errorMessage(e)),
    );
  }, [ssoComplete, navigate]);

  if (error) {
    return (
      <AuthShell title="Single sign-on failed" subtitle="Your identity provider's sign-in could not be completed.">
        <FormError message={error} />
        <Link to="/sso" className="btn-primary w-full">Try again</Link>
      </AuthShell>
    );
  }
  if (!outcome) {
    return (
      <AuthShell title="Signing you in…" subtitle="Verifying the response from your identity provider.">
        <div className="flex justify-center py-6"><Spinner className="h-6 w-6" /></div>
      </AuthShell>
    );
  }
  if (outcome.kind === 'two_factor') return <SsoTwoFactor challenge={outcome.challenge} onCancel={() => { cancelTwoFactor(); navigate('/', { replace: true }); }} />;
  if (outcome.kind === 'link') return <SsoLink email={outcome.email} orgName={outcome.orgName} />;
  if (outcome.kind === 'provision') return <SsoProvision outcome={outcome} />;
  return null;
}

function SsoTwoFactor({ challenge, onCancel }: { challenge: TwoFactorChallenge; onCancel: () => void }) {
  const navigate = useNavigate();
  return (
    <AuthShell title="Two-step login" subtitle="Your Enclavier account also has two-step login.">
      <TwoFactorStep challenge={challenge} onCancel={onCancel} onDone={() => navigate('/vault', { replace: true })} />
    </AuthShell>
  );
}

/** Existing account on a domain the organization doesn't own: prove the master password once. */
function SsoLink({ email, orgName }: { email: string; orgName: string }) {
  const navigate = useNavigate();
  return (
    <AuthShell title="Link your account" subtitle={`Sign in once with your master password to connect ${email} to ${orgName}'s single sign-on.`}>
      <p className="mb-4 text-sm text-slate-600 dark:text-slate-300">
        An Enclavier account already exists for this address. Linking needs your master password so that nobody else can attach it to an
        organization.
      </p>
      <button className="btn-primary w-full" onClick={() => navigate(`/?email=${encodeURIComponent(email)}`, { replace: true })}>
        <KeyRound className="h-4 w-4" /> Sign in to link
      </button>
    </AuthShell>
  );
}

function SsoProvision({ outcome }: { outcome: Extract<SsoOutcome, { kind: 'provision' }> }) {
  const ssoProvision = useSession((s) => s.ssoProvision);
  const navigate = useNavigate();
  const [name, setName] = useState(outcome.name);
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (password.length < 12) return setError('Use at least 12 characters for your master password.');
    if (password !== confirm) return setError('Passwords do not match.');
    setBusy(true);
    setError(null);
    try {
      await ssoProvision(outcome.provisionToken, outcome.org, name.trim(), password);
      navigate('/vault', { replace: true });
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  return (
    <AuthShell title={`Welcome to ${outcome.orgName}`} subtitle={`Create the Enclavier vault for ${outcome.email}.`}>
      <FormError message={error} />
      <p className="mb-4 rounded-lg bg-brand-50 p-3 text-xs text-brand-800 dark:bg-brand-500/10 dark:text-brand-300">
        Single sign-on proves who you are, but only your master password can decrypt your vault. Enclavier never sees it. After this, you can
        trust this browser so that single sign-on alone unlocks it.
      </p>
      <form onSubmit={submit} className="space-y-4">
        <div>
          <label className="label" htmlFor="p-name">Name</label>
          <input id="p-name" className="input" required value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <div>
          <label className="label" htmlFor="p-password">Master password</label>
          <PasswordInput id="p-password" value={password} onChange={setPassword} autoComplete="new-password" autoFocus />
          <StrengthMeter password={password} />
        </div>
        <div>
          <label className="label" htmlFor="p-confirm">Confirm master password</label>
          <PasswordInput id="p-confirm" value={confirm} onChange={setConfirm} autoComplete="new-password" />
        </div>
        <label className="flex items-start gap-2.5 rounded-lg bg-amber-50 p-3 text-xs text-amber-800 dark:bg-amber-950/40 dark:text-amber-200">
          <input type="checkbox" className="mt-0.5" checked={ack} onChange={(e) => setAck(e.target.checked)} />
          I understand Enclavier can't reset my master password unless my organization enrolls me in account recovery.
        </label>
        <button className="btn-primary w-full" disabled={busy || !ack || !name || !password || !confirm}>
          {busy && <Spinner />} {busy ? 'Generating keys…' : 'Create vault'}
        </button>
      </form>
    </AuthShell>
  );
}
