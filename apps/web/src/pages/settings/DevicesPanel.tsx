import { useCallback, useEffect, useState } from 'react';
import { Check, Laptop, ShieldCheck, Trash2, X } from 'lucide-react';
import { fingerprint, fromB64 } from '@enclavier/crypto';
import type { TrustedDevice } from '@enclavier/shared';
import { api } from '../../lib/api';
import { deviceFor } from '../../lib/deviceStore';
import { useSession } from '../../lib/session';
import { Modal, Spinner } from '../../components/ui';
import { errorMessage, toast } from '../../components/Toast';

/** Pending approval requests for the signed-in account (polled, for the banner). */
export function usePendingDevices(enabled: boolean) {
  const [pending, setPending] = useState<TrustedDevice[]>([]);
  useEffect(() => {
    if (!enabled) return;
    let alive = true;
    const load = () =>
      api<TrustedDevice[]>('GET', '/api/devices').then(
        (all) => alive && setPending(all.filter((d) => d.status === 'pending' && !d.adminApprovalOrg)),
        () => undefined,
      );
    void load();
    const timer = setInterval(load, 30_000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [enabled]);
  return pending;
}

export function DevicesPanel() {
  const { profile, sso, isTrustedDevice, trustThisDevice, forgetThisDevice, approveDevice } = useSession();
  const [devices, setDevices] = useState<TrustedDevice[] | null>(null);
  const [reviewing, setReviewing] = useState<TrustedDevice | null>(null);
  const [busy, setBusy] = useState(false);
  const thisDevice = profile ? deviceFor(profile.email)?.deviceId : undefined;

  const load = useCallback(() => api<TrustedDevice[]>('GET', '/api/devices').then(setDevices, (e) => toast(errorMessage(e), 'error')), []);
  useEffect(() => void load(), [load]);

  async function run(fn: () => Promise<unknown>, done: string) {
    setBusy(true);
    try {
      await fn();
      toast(done);
      await load();
    } catch (e) {
      toast(errorMessage(e), 'error');
    } finally {
      setBusy(false);
      setReviewing(null);
    }
  }

  if (!devices) return <Spinner />;
  const trusted = isTrustedDevice();
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3 rounded-lg bg-slate-50 p-3 text-sm dark:bg-slate-800/50">
        <ShieldCheck className={`h-5 w-5 ${trusted ? 'text-emerald-500' : 'text-slate-400'}`} />
        <span className="flex-1">
          {trusted
            ? `This browser is trusted${sso ? `: signing in with ${sso.name} SSO unlocks it without your master password` : ''}.`
            : 'This browser is not trusted. Trusted browsers unlock with single sign-on alone.'}
        </span>
        {trusted ? (
          <button className="btn-secondary text-xs" disabled={busy} onClick={() => run(forgetThisDevice, 'This browser is no longer trusted')}>
            Stop trusting
          </button>
        ) : (
          <button className="btn-primary text-xs" disabled={busy} onClick={() => run(trustThisDevice, 'This browser is now trusted')}>
            Trust this browser
          </button>
        )}
      </div>

      {devices.length === 0 ? (
        <p className="text-sm text-slate-500">No trusted devices yet.</p>
      ) : (
        <ul className="divide-y divide-slate-100 dark:divide-slate-800">
          {devices.map((d) => (
            <li key={d.id} className="flex items-center gap-3 py-3">
              <Laptop className="h-5 w-5 text-slate-400" />
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-medium">
                  {d.name}
                  {d.id === thisDevice && <span className="ml-2 rounded bg-emerald-100 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-700 uppercase dark:bg-emerald-500/15 dark:text-emerald-400">This browser</span>}
                  {d.status === 'pending' && <span className="ml-2 rounded bg-amber-100 px-1.5 py-0.5 text-[10px] font-semibold text-amber-700 uppercase dark:bg-amber-500/15 dark:text-amber-400">Waiting for approval</span>}
                </div>
                <div className="truncate text-xs text-slate-500">
                  {d.status === 'pending'
                    ? d.adminApprovalOrg
                      ? `Asked the administrators of ${d.adminApprovalOrg.name} · ${new Date(d.createdAt).toLocaleString()}`
                      : `Requested ${new Date(d.createdAt).toLocaleString()}`
                    : `Trusted ${d.trustedAt ? new Date(d.trustedAt).toLocaleDateString() : ''}${d.lastUsedAt ? ` · last unlock ${new Date(d.lastUsedAt).toLocaleString()}` : ''}`}
                </div>
              </div>
              {d.status === 'pending' && d.id !== thisDevice && (
                <button className="btn-primary text-xs" onClick={() => setReviewing(d)}>Review</button>
              )}
              {d.status === 'trusted' && d.id !== thisDevice && (
                <button className="btn-ghost text-xs" disabled={busy} onClick={() => run(() => api('DELETE', `/api/devices/${d.id}`), 'Device removed')}>
                  <Trash2 className="h-3.5 w-3.5" /> Remove
                </button>
              )}
            </li>
          ))}
        </ul>
      )}

      {reviewing && (
        <Modal
          title="Approve this device?"
          onClose={() => setReviewing(null)}
          footer={
            <>
              <button className="btn-secondary" disabled={busy} onClick={() => run(() => api('POST', `/api/devices/${reviewing.id}/deny`), 'Request denied')}>
                <X className="h-4 w-4" /> Deny
              </button>
              <button className="btn-primary" disabled={busy} onClick={() => run(() => approveDevice(reviewing), 'Device approved')}>
                {busy ? <Spinner /> : <Check className="h-4 w-4" />} Approve
              </button>
            </>
          }
        >
          <p className="text-sm text-slate-600 dark:text-slate-300">
            <strong>{reviewing.name}</strong> is asking to open your vault. Approve only if you are signing in on it right now and it shows this
            exact phrase:
          </p>
          <p className="mt-3 rounded-lg bg-slate-100 px-3 py-2 text-center font-mono text-sm dark:bg-slate-800">{fingerprint(fromB64(reviewing.publicKey))}</p>
          <p className="mt-3 text-xs text-slate-500">Approving gives that device your vault key. You can remove it here at any time.</p>
        </Modal>
      )}
    </div>
  );
}
