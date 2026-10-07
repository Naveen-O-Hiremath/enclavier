import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { Download, Laptop, LogOut, ShieldCheck } from 'lucide-react';
import { InvalidPasswordError, publicKeyFingerprint } from '@enclavier/crypto';
import type { AuditEvent, Session } from '@enclavier/shared';
import { api } from '../lib/api';
import { useSession } from '../lib/session';
import { useSettings } from '../lib/settings';
import { Modal, PasswordInput, Spinner, StrengthMeter } from '../components/ui';
import { TwoFactorPanel } from './settings/TwoFactorPanel';
import { EmergencyPanel } from './settings/EmergencyPanel';
import { DevicesPanel } from './settings/DevicesPanel';
import { Link } from 'react-router-dom';
import { useEffectivePolicy } from '../lib/policy';
import { checkStrength, SCORE_LABELS } from '../lib/strength';
import { errorMessage, toast } from '../components/Toast';

function Panel({ title, description, children }: { title: string; description?: string; children: ReactNode }) {
  return (
    <section className="card p-5">
      <h2 className="font-semibold">{title}</h2>
      {description && <p className="mt-0.5 text-sm text-slate-500">{description}</p>}
      <div className="mt-4">{children}</div>
    </section>
  );
}

const friendlyError = (e: unknown) => (e instanceof InvalidPasswordError ? 'Master password is incorrect' : errorMessage(e));

/** Returns a message when the password does not meet the organizations' master password policy. */
export async function masterPolicyViolation(password: string, p: ReturnType<typeof useEffectivePolicy>['masterPassword']): Promise<string | null> {
  if (!p) return null;
  if ([...password].length < p.minLength) return `${p.sources.join(', ')} requires at least ${p.minLength} characters`;
  const { score } = await checkStrength(password);
  if (score < p.minScore) return `${p.sources.join(', ')} requires strength "${SCORE_LABELS[p.minScore]}" or better (this is "${SCORE_LABELS[score]}")`;
  return null;
}

function ChangePassword() {
  const changePassword = useSession((s) => s.changePassword);
  const policy = useEffectivePolicy();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (next.length < 12) return toast('Use at least 12 characters', 'error');
    if (next !== confirm) return toast('New passwords do not match', 'error');
    const violation = await masterPolicyViolation(next, policy.masterPassword);
    if (violation) return toast(violation, 'error');
    setBusy(true);
    try {
      await changePassword(current, next);
      setCurrent('');
      setNext('');
      setConfirm('');
      toast('Master password changed. Other devices were signed out.');
    } catch (err) {
      toast(friendlyError(err), 'error');
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="grid gap-4 sm:max-w-md">
      <div>
        <label className="label">Current master password</label>
        <PasswordInput value={current} onChange={setCurrent} autoComplete="current-password" />
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
      <div>
        <button className="btn-primary" disabled={busy || !current || !next || !confirm}>
          {busy && <Spinner />} Change master password
        </button>
      </div>
    </form>
  );
}

function Sessions() {
  const [sessions, setSessions] = useState<Session[] | null>(null);
  const load = () => api<Session[]>('GET', '/api/account/sessions').then(setSessions, (e) => toast(errorMessage(e), 'error'));
  useEffect(() => void load(), []);

  async function revoke(id: string) {
    try {
      await api('DELETE', `/api/account/sessions/${id}`);
      toast('Session signed out');
      void load();
    } catch (e) {
      toast(errorMessage(e), 'error');
    }
  }

  if (!sessions) return <Spinner />;
  return (
    <ul className="divide-y divide-slate-100 dark:divide-slate-800">
      {sessions.map((s) => (
        <li key={s.id} className="flex items-center gap-3 py-3">
          <Laptop className="h-5 w-5 text-slate-400" />
          <div className="min-w-0 flex-1">
            <div className="truncate text-sm font-medium">
              {s.deviceName ?? 'Unknown device'}
              {s.current && <span className="ml-2 rounded bg-emerald-100 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-700 uppercase dark:bg-emerald-500/15 dark:text-emerald-400">This device</span>}
            </div>
            <div className="truncate text-xs text-slate-500">
              {s.ip ?? 'unknown IP'} · last active {new Date(s.lastUsedAt).toLocaleString()}
            </div>
          </div>
          {!s.current && (
            <button className="btn-ghost text-xs" onClick={() => revoke(s.id)}>
              <LogOut className="h-3.5 w-3.5" /> Sign out
            </button>
          )}
        </li>
      ))}
    </ul>
  );
}

const ACTION_LABELS: Record<string, string> = {
  'user.register': 'Account created',
  'user.login': 'Signed in',
  'user.login_failed': 'Failed sign-in attempt',
  'user.logout': 'Signed out',
  'user.password_changed': 'Master password changed',
  'session.refresh_reuse_detected': 'Session revoked: token reuse detected',
  'session.revoked': 'Session signed out remotely',
  'folder.created': 'Folder created',
  'folder.updated': 'Folder renamed',
  'folder.deleted': 'Folder deleted',
  'item.created': 'Item created',
  'item.updated': 'Item updated',
  'item.trashed': 'Item moved to trash',
  'item.restored': 'Item restored',
  'item.deleted': 'Item permanently deleted',
  'vault.exported': 'Vault exported',
  'user.sso_linked': 'Linked to organization single sign-on',
  'user.sso_provisioned': 'Account created with single sign-on',
  'device.trusted': 'Browser trusted for SSO unlock',
  'device.approval_requested': 'New device asked for approval',
  'device.approved': 'New device approved',
  'device.denied': 'Device request denied',
  'device.removed': 'Trusted device removed',
};

function Activity() {
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  useEffect(() => {
    api<AuditEvent[]>('GET', '/api/account/events?limit=50').then(setEvents, (e) => toast(errorMessage(e), 'error'));
  }, []);
  if (!events) return <Spinner />;
  return (
    <div className="max-h-80 overflow-y-auto">
      <table className="w-full text-sm">
        <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
          {events.map((e) => (
            <tr key={e.id}>
              <td className={`py-2 pr-3 ${e.action.includes('failed') || e.action.includes('reuse') ? 'text-red-600' : ''}`}>{ACTION_LABELS[e.action] ?? e.action}</td>
              <td className="py-2 pr-3 text-xs text-slate-500">{e.ip}</td>
              <td className="py-2 text-right text-xs whitespace-nowrap text-slate-500">{new Date(e.createdAt).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ReauthDialog(props: { title: string; body: ReactNode; action: string; danger?: boolean; onConfirm: (password: string) => Promise<void>; onClose: () => void }) {
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await props.onConfirm(password);
      props.onClose();
    } catch (err) {
      toast(friendlyError(err), 'error');
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal title={props.title} onClose={props.onClose}>
      <form onSubmit={submit} className="space-y-4">
        <div className="text-sm text-slate-600 dark:text-slate-300">{props.body}</div>
        <div>
          <label className="label">Master password</label>
          <PasswordInput value={password} onChange={setPassword} autoFocus autoComplete="current-password" />
        </div>
        <div className="flex justify-end gap-2">
          <button type="button" className="btn-secondary" onClick={props.onClose}>Cancel</button>
          <button className={props.danger ? 'btn-danger' : 'btn-primary'} disabled={busy || !password}>
            {busy && <Spinner />} {props.action}
          </button>
        </div>
      </form>
    </Modal>
  );
}

export function SettingsPage() {
  const { profile, bundle, items, folders, verifyPassword, deleteAccount, logout } = useSession();
  const settings = useSettings();
  const policy = useEffectivePolicy();
  const lockCap = policy.maxAutoLockMinutes?.value;
  const clipCap = policy.maxClipboardSeconds?.value;
  const exportBlocked = policy.exportDisabledBy.length > 0;
  const [dialog, setDialog] = useState<'export' | 'delete' | null>(null);

  async function exportVault(password: string) {
    await verifyPassword(password);
    await api('POST', '/api/account/events/export');
    const payload = {
      exportedAt: new Date().toISOString(),
      folders,
      // Personal vault only: organization data (incl. "use"-only items) is governed by the org.
      items: items.filter((i) => !i.deletedAt && !i.orgId).map((i) => ({ id: i.id, folderId: i.folderId, ...i.data })),
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `enclavier-export-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    toast('Export downloaded. It is NOT encrypted — store it safely and delete it after use.');
  }

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-3xl space-y-5 p-6">
        <h1 className="text-lg font-semibold">Settings</h1>

        <Panel title="Account">
          <dl className="grid gap-3 text-sm sm:grid-cols-2">
            <div><dt className="text-xs text-slate-500">Name</dt><dd>{profile?.name}</dd></div>
            <div><dt className="text-xs text-slate-500">E-mail</dt><dd>{profile?.email}</dd></div>
            <div>
              <dt className="text-xs text-slate-500">Key derivation</dt>
              <dd className="flex items-center gap-1.5">
                <ShieldCheck className="h-4 w-4 text-emerald-500" />
                Argon2id · {Math.round((bundle?.kdf.memory ?? 0) / 1024)} MiB · {bundle?.kdf.iterations} iterations · {bundle?.kdf.parallelism} lanes
              </dd>
            </div>
            <div><dt className="text-xs text-slate-500">Encryption</dt><dd>XChaCha20-Poly1305, per-item keys</dd></div>
            <div className="sm:col-span-2">
              <dt className="text-xs text-slate-500">Your key fingerprint</dt>
              <dd className="mt-0.5 font-mono text-sm">{bundle ? publicKeyFingerprint(bundle.publicKey) : ''}</dd>
              <dd className="mt-0.5 text-xs text-slate-500">Read this to an organization admin when they confirm your membership.</dd>
            </div>
          </dl>
        </Panel>

        <Panel title="Master password" description="Changing it re-wraps your vault key; your items are not re-encrypted. Other devices are signed out.">
          <ChangePassword />
        </Panel>

        <Panel title="Two-step login" description="Require a second factor, in addition to your master password, on new devices.">
          <TwoFactorPanel />
        </Panel>

        <Panel title="Emergency access" description="Let a trusted person request read-only access to your personal vault if something happens to you.">
          <EmergencyPanel />
        </Panel>

        <Panel title="Vault security">
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label className="label">Auto-lock after inactivity</label>
              <select className="input" value={lockCap && (settings.autoLockMinutes === 0 || settings.autoLockMinutes > lockCap) ? Math.max(...[1, 5, 15, 30, 60, 240].filter((m) => m <= lockCap), 1) : settings.autoLockMinutes} onChange={(e) => settings.update({ autoLockMinutes: Number(e.target.value) })}>
                {[1, 5, 15, 30, 60, 240].filter((m) => !lockCap || m <= lockCap).map((m) => <option key={m} value={m}>{m < 60 ? `${m} minute${m > 1 ? 's' : ''}` : `${m / 60} hour${m > 60 ? 's' : ''}`}</option>)}
                {!lockCap && <option value={0}>Never</option>}
              </select>
            </div>
            <div>
              <label className="label">Clear clipboard after</label>
              <select className="input" value={clipCap && (settings.clipboardClearSeconds === 0 || settings.clipboardClearSeconds > clipCap) ? Math.max(...[10, 20, 30, 60, 120].filter((s) => s <= clipCap), 10) : settings.clipboardClearSeconds} onChange={(e) => settings.update({ clipboardClearSeconds: Number(e.target.value) })}>
                {[10, 20, 30, 60, 120].filter((s) => !clipCap || s <= clipCap).map((s) => <option key={s} value={s}>{s} seconds</option>)}
                {!clipCap && <option value={0}>Never</option>}
              </select>
            </div>
          </div>
          {(lockCap || clipCap) && (
            <p className="mt-2 text-xs text-slate-500">
              {lockCap && `Auto-lock is capped at ${lockCap} minute(s) by ${policy.maxAutoLockMinutes!.sources.join(', ')}. `}
              {clipCap && `Clipboard clearing is capped at ${clipCap} seconds by ${policy.maxClipboardSeconds!.sources.join(', ')}.`}
            </p>
          )}
          <label className="mt-4 flex items-center gap-2 text-sm">
            <input type="checkbox" checked={settings.lockOnHide} onChange={(e) => settings.update({ lockOnHide: e.target.checked })} />
            Lock when this tab is hidden or minimised
          </label>
        </Panel>

        <Panel title="Devices" description="Trusted browsers unlock with single sign-on. New devices can be approved from here instead of typing your master password.">
          <DevicesPanel />
        </Panel>
        <Panel title="Active sessions" description="Devices currently signed in to your account.">
          <Sessions />
        </Panel>

        <Panel title="Recent activity" description="From the tamper-evident audit log.">
          <Activity />
        </Panel>

        <Panel title="Data">
          <div className="flex flex-wrap gap-2">
            <button
              className="btn-secondary"
              disabled={exportBlocked}
              title={exportBlocked ? `Export is disabled by ${policy.exportDisabledBy.join(', ')}` : undefined}
              onClick={() => setDialog('export')}
            >
              <Download className="h-4 w-4" /> Export vault
            </button>
            <button className="btn-secondary" onClick={() => void logout()}><LogOut className="h-4 w-4" /> Log out</button>
          </div>
          <p className="mt-4 text-xs text-slate-500">
            Hold break-glass recovery shares for an organization? <Link to="/recover-org" className="text-brand-600 hover:underline dark:text-brand-400">Recover an organization</Link>
          </p>
        </Panel>

        <section className="card border-red-200 p-5 dark:border-red-900/60">
          <h2 className="font-semibold text-red-700 dark:text-red-400">Delete account</h2>
          <p className="mt-0.5 text-sm text-slate-500">Permanently erases your account and every item in your vault.</p>
          <button className="btn-danger mt-4" onClick={() => setDialog('delete')}>Delete account</button>
        </section>
      </div>

      {dialog === 'export' && (
        <ReauthDialog
          title="Export vault"
          body="The export contains the items in your personal vault in plain text (organization items are not included). Confirm your master password to continue."
          action="Export"
          onConfirm={exportVault}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog === 'delete' && (
        <ReauthDialog
          title="Delete account permanently?"
          body={<>All {items.length} items and {folders.length} folders will be erased. This cannot be undone.</>}
          action="Delete account"
          danger
          onConfirm={deleteAccount}
          onClose={() => setDialog(null)}
        />
      )}
    </div>
  );
}
