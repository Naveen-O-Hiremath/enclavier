import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { AlertTriangle, Building2, CheckCircle2, KeyRound, Laptop, LifeBuoy, MailWarning, ShieldAlert } from 'lucide-react';
import { usePendingDevices } from './settings/DevicesPanel';
import { InvalidPasswordError } from '@enclavier/crypto';
import { enrollAccountRecovery, resendVerification, verifyEmail } from '../lib/security';
import { useSession, type VaultOrg } from '../lib/session';
import { Logo, Modal, PasswordInput, Spinner, StrengthMeter } from '../components/ui';
import { errorMessage, toast } from '../components/Toast';
import { useEffectivePolicy } from '../lib/policy';
import { SCORE_LABELS } from '../lib/strength';
import { masterPolicyViolation } from './SettingsPage';

/** /verify-email?user=&token= — works signed in or out. */
export function VerifyEmailPage() {
  const location = useLocation();
  const status = useSession((s) => s.status);
  const sync = useSession((s) => s.sync);
  const params = useMemo(() => new URLSearchParams(location.search), [location.search]);
  const [state, setState] = useState<'busy' | 'ok' | 'error'>('busy');
  const [error, setError] = useState('');

  useEffect(() => {
    verifyEmail(params.get('user') ?? '', params.get('token') ?? '').then(
      () => {
        setState('ok');
        if (useSession.getState().status === 'unlocked') void sync();
      },
      (e) => {
        setError(errorMessage(e));
        setState('error');
      },
    );
  }, [params, sync]);

  return (
    <div className="flex min-h-full items-center justify-center px-4 py-12">
      <div className="w-full max-w-sm text-center">
        <div className="mb-8 flex justify-center"><Logo size="lg" /></div>
        <div className="card p-6">
          {state === 'busy' && <Spinner className="h-6 w-6" />}
          {state === 'ok' && (
            <>
              <CheckCircle2 className="mx-auto h-10 w-10 text-emerald-500" />
              <h1 className="mt-3 text-lg font-semibold">E-mail verified</h1>
            </>
          )}
          {state === 'error' && (
            <>
              <AlertTriangle className="mx-auto h-10 w-10 text-amber-500" />
              <h1 className="mt-3 text-lg font-semibold">Couldn't verify</h1>
              <p className="mt-1 text-sm text-slate-500">{error}</p>
            </>
          )}
          <Link to="/vault" className="btn-secondary mt-5">{status === 'loggedOut' ? 'Sign in' : 'Open vault'}</Link>
        </div>
      </div>
    </div>
  );
}

/** After an admin recovery the temporary password must be replaced before anything else. */
export function ForcePasswordChange() {
  const { profile, changePassword, logout, masterPasswordViolation } = useSession();
  const policy = useEffectivePolicy();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const byAdmin = !!profile?.forcePasswordChange;
  if (!byAdmin && !masterPasswordViolation) return null;

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (next.length < 12) return toast('Use at least 12 characters', 'error');
    if (next !== confirm) return toast('Passwords do not match', 'error');
    if (next === current) return toast('Choose a different password', 'error');
    const violation = await masterPolicyViolation(next, policy.masterPassword);
    if (violation) return toast(violation, 'error');
    setBusy(true);
    try {
      await changePassword(current, next);
      toast('Master password updated');
    } catch (err) {
      toast(err instanceof InvalidPasswordError ? 'The current password is incorrect' : errorMessage(err), 'error');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title="Choose a new master password" onClose={() => undefined}>
      <form onSubmit={submit} className="space-y-4">
        <p className="flex gap-2 text-sm text-slate-600 dark:text-slate-300">
          <KeyRound className="mt-0.5 h-4 w-4 shrink-0 text-brand-600" />
          {byAdmin
            ? 'An administrator reset your master password using account recovery. Replace the temporary password now. Only you will know the new one.'
            : `${masterPasswordViolation!.sources.join(', ')} requires a master password of at least ${masterPasswordViolation!.minLength} characters with strength "${SCORE_LABELS[masterPasswordViolation!.minScore]}" or better. Please choose a stronger one.`}
        </p>
        <div>
          <label className="label">{byAdmin ? 'Temporary password' : 'Current master password'}</label>
          <PasswordInput value={current} onChange={setCurrent} autoFocus autoComplete="current-password" />
        </div>
        <div>
          <label className="label">New master password</label>
          <PasswordInput value={next} onChange={setNext} autoComplete="new-password" />
          <StrengthMeter password={next} />
        </div>
        <div>
          <label className="label">Confirm new master password</label>
          <PasswordInput value={confirm} onChange={setConfirm} autoComplete="new-password" />
        </div>
        <div className="flex justify-between gap-2">
          <button type="button" className="btn-ghost" onClick={() => void logout()}>Log out</button>
          <button className="btn-primary" disabled={busy || !current || !next || !confirm}>{busy && <Spinner />} Save</button>
        </div>
      </form>
    </Modal>
  );
}

function RecoveryEnrollDialog({ org, onClose }: { org: VaultOrg; onClose: () => void }) {
  const [busy, setBusy] = useState(false);
  async function enroll() {
    setBusy(true);
    try {
      await enrollAccountRecovery(org);
      toast('Enrolled in account recovery');
      onClose();
    } catch (e) {
      toast(errorMessage(e), 'error');
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      title={`Account recovery for ${org.name}`}
      onClose={onClose}
      footer={
        <>
          <button className="btn-secondary" onClick={onClose}>Not now</button>
          <button className="btn-primary" onClick={enroll} disabled={busy}>{busy && <Spinner />} Enroll</button>
        </>
      }
    >
      <div className="space-y-3 text-sm text-slate-600 dark:text-slate-300">
        <p>If you forget your master password, an administrator of <strong>{org.name}</strong> can reset it for you.</p>
        <p className="rounded-lg bg-amber-50 p-3 text-amber-900 dark:bg-amber-950/40 dark:text-amber-200">
          <strong>Important:</strong> enrolling seals your vault key to the organization's recovery key. Its administrators could then open your
          <strong> personal</strong> vault as well as shared items. Every reset is audited and e-mailed to you.
        </p>
      </div>
    </Modal>
  );
}

/** Account-level notices shown above every page. */
export function AccountBanners() {
  const { profile, organizations, status, sso, isTrustedDevice, trustThisDevice } = useSession();
  const navigate = useNavigate();
  const pendingDevices = usePendingDevices(status === 'unlocked');
  const dismissKey = `enclavier.trust-prompt.${profile?.id ?? ''}`;
  const [trustDismissed, setTrustDismissed] = useState(() => {
    try {
      return localStorage.getItem(dismissKey) === '1';
    } catch {
      return true;
    }
  });
  const [enrollOrg, setEnrollOrg] = useState<VaultOrg | null>(null);
  const [resent, setResent] = useState(false);
  const attempted = useRef(new Set<string>());

  const blocked = organizations.filter((o) => o.blockedByPolicy === 'require_2fa');
  const needsRecovery = organizations.filter(
    (o) => o.status === 'confirmed' && !o.blockedByPolicy && o.policies.accountRecovery && !o.recoveryEnrolled && o.recoveryPublicKey,
  );
  const autoEnroll = needsRecovery.filter((o) => o.policies.accountRecoveryAutoEnroll && !attempted.current.has(o.id));
  const optional = needsRecovery.filter((o) => !o.policies.accountRecoveryAutoEnroll);

  // Orgs that require enrollment get it automatically (the org's policy was disclosed when joining).
  useEffect(() => {
    if (status !== 'unlocked' || autoEnroll.length === 0) return;
    // Each org is tried once per session so a failure can't loop.
    for (const org of autoEnroll) attempted.current.add(org.id);
    (async () => {
      for (const org of autoEnroll) {
        try {
          await enrollAccountRecovery(org);
          toast(`${org.name} enrolled you in account recovery`);
        } catch (e) {
          toast(errorMessage(e), 'error');
        }
      }
    })();
  }, [status, autoEnroll]);

  const Banner = ({ tone, icon, children }: { tone: 'amber' | 'red' | 'brand'; icon: ReactNode; children: ReactNode }) => {
    const tones = {
      amber: 'border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-900/50 dark:bg-amber-950/30 dark:text-amber-200',
      red: 'border-red-200 bg-red-50 text-red-900 dark:border-red-900/50 dark:bg-red-950/30 dark:text-red-200',
      brand: 'border-brand-100 bg-brand-50 text-brand-800 dark:border-brand-500/20 dark:bg-brand-500/10 dark:text-brand-300',
    };
    return <div className={`flex flex-wrap items-center gap-2 border-b px-4 py-2 text-sm ${tones[tone]}`}>{icon}{children}</div>;
  };

  return (
    <>
      {pendingDevices.map((d) => (
        <Banner key={d.id} tone="amber" icon={<Laptop className="h-4 w-4" />}>
          <span className="flex-1"><strong>{d.name}</strong> is asking to open your vault.</span>
          <button className="btn-secondary px-2.5 py-1 text-xs" onClick={() => navigate('/settings')}>Review</button>
        </Banner>
      ))}
      {sso && status === 'unlocked' && !trustDismissed && !isTrustedDevice() && (
        <Banner tone="brand" icon={<Building2 className="h-4 w-4" />}>
          <span className="flex-1">Trust this browser so that signing in with <strong>{sso.name}</strong> SSO unlocks your vault without the master password?</span>
          <button
            className="btn-primary px-2.5 py-1 text-xs"
            onClick={() => trustThisDevice().then(() => toast('This browser is now trusted'), (e) => toast(errorMessage(e), 'error'))}
          >
            Trust
          </button>
          <button
            className="btn-ghost px-2.5 py-1 text-xs"
            onClick={() => {
              try {
                localStorage.setItem(dismissKey, '1');
              } catch {
                /* ignore */
              }
              setTrustDismissed(true);
            }}
          >
            Not now
          </button>
        </Banner>
      )}
      {blocked.map((o) => (
        <Banner key={o.id} tone="red" icon={<ShieldAlert className="h-4 w-4" />}>
          <span className="flex-1"><strong>{o.name}</strong> requires two-step login. Its shared items are hidden until you turn it on.</span>
          <button className="btn-secondary px-2.5 py-1 text-xs" onClick={() => navigate('/settings')}>Set up two-step login</button>
        </Banner>
      ))}
      {optional.map((o) => (
        <Banner key={o.id} tone="brand" icon={<LifeBuoy className="h-4 w-4" />}>
          <span className="flex-1"><strong>{o.name}</strong> offers master password recovery.</span>
          <button className="btn-secondary px-2.5 py-1 text-xs" onClick={() => setEnrollOrg(o)}>Learn more</button>
        </Banner>
      ))}
      {profile && !profile.emailVerified && (
        <Banner tone="amber" icon={<MailWarning className="h-4 w-4" />}>
          <span className="flex-1">Please verify {profile.email}. We sent you a link.</span>
          <button
            className="btn-secondary px-2.5 py-1 text-xs"
            disabled={resent}
            onClick={() => resendVerification().then(() => { setResent(true); toast('Verification e-mail sent'); }, (e) => toast(errorMessage(e), 'error'))}
          >
            {resent ? 'Sent' : 'Resend'}
          </button>
        </Banner>
      )}
      {enrollOrg && <RecoveryEnrollDialog org={enrollOrg} onClose={() => setEnrollOrg(null)} />}
    </>
  );
}
