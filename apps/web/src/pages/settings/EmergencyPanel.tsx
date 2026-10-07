import { useEffect, useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { Clock, Fingerprint, HeartHandshake, Trash2, UserPlus } from 'lucide-react';
import { publicKeyFingerprint } from '@enclavier/crypto';
import type { EmergencyGrant, EmergencyOverview } from '@enclavier/shared';
import {
  confirmEmergencyContact,
  decideEmergency,
  getEmergencyOverview,
  initiateEmergency,
  inviteEmergencyContact,
  removeEmergency,
} from '../../lib/security';
import { Modal, Spinner } from '../../components/ui';
import { errorMessage, toast } from '../../components/Toast';
import { Badge } from '../admin/shared';

const STATUS: Record<EmergencyGrant['status'], { label: string; tone: 'slate' | 'amber' | 'green' | 'red' | 'brand' }> = {
  invited: { label: 'Invited', tone: 'slate' },
  accepted: { label: 'Needs your confirmation', tone: 'amber' },
  confirmed: { label: 'Active', tone: 'green' },
  recovery_initiated: { label: 'Access requested', tone: 'red' },
  recovery_approved: { label: 'Access granted', tone: 'brand' },
};

function timeLeft(iso: string | null): string {
  if (!iso) return '';
  const ms = new Date(iso).getTime() - Date.now();
  if (ms <= 0) return 'now';
  const h = Math.ceil(ms / 3_600_000);
  return h > 48 ? `in ${Math.ceil(h / 24)} days` : `in ${h} hours`;
}

export function EmergencyPanel() {
  const navigate = useNavigate();
  const [data, setData] = useState<EmergencyOverview | null>(null);
  const [inviting, setInviting] = useState(false);
  const [confirming, setConfirming] = useState<EmergencyGrant | null>(null);
  const [email, setEmail] = useState('');
  const [waitDays, setWaitDays] = useState(7);
  const [busy, setBusy] = useState(false);

  const reload = () => getEmergencyOverview().then(setData, (e) => toast(errorMessage(e), 'error'));
  useEffect(() => void reload(), []);

  async function act(fn: () => Promise<unknown>, done: string) {
    setBusy(true);
    try {
      await fn();
      toast(done);
      await reload();
    } catch (e) {
      toast(errorMessage(e), 'error');
    } finally {
      setBusy(false);
    }
  }

  async function invite(e: FormEvent) {
    e.preventDefault();
    await act(() => inviteEmergencyContact(email.trim().toLowerCase(), waitDays), 'Invitation sent');
    setInviting(false);
    setEmail('');
  }

  if (!data) return <Spinner />;

  return (
    <div className="space-y-6">
      <div>
        <div className="mb-2 flex items-center justify-between">
          <h3 className="text-sm font-medium">My emergency contacts</h3>
          <button className="btn-secondary px-2.5 py-1 text-xs" onClick={() => setInviting(true)}><UserPlus className="h-3.5 w-3.5" /> Add contact</button>
        </div>
        {data.granted.length === 0 ? (
          <p className="text-sm text-slate-500">Nobody can request access to your vault. Add a trusted person in case you're ever unable to.</p>
        ) : (
          <ul className="divide-y divide-slate-100 rounded-lg border border-slate-200 dark:divide-slate-800 dark:border-slate-800">
            {data.granted.map((g) => (
              <li key={g.id} className="flex flex-wrap items-center gap-3 px-3 py-2.5">
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm">{g.name ?? g.email}</div>
                  <div className="text-xs text-slate-500">
                    {g.email} · {g.waitDays}-day wait
                    {g.status === 'recovery_initiated' && ` · access unlocks ${timeLeft(g.autoApproveAt)}`}
                  </div>
                </div>
                <Badge tone={STATUS[g.status].tone}>{STATUS[g.status].label}</Badge>
                {g.status === 'accepted' && <button className="btn-primary px-2.5 py-1 text-xs" onClick={() => setConfirming(g)}>Confirm</button>}
                {g.status === 'recovery_initiated' && (
                  <>
                    <button className="btn-danger px-2.5 py-1 text-xs" disabled={busy} onClick={() => act(() => decideEmergency(g.id, false), 'Request rejected')}>Reject</button>
                    <button className="btn-secondary px-2.5 py-1 text-xs" disabled={busy} onClick={() => act(() => decideEmergency(g.id, true), 'Access granted')}>Approve now</button>
                  </>
                )}
                <button className="icon-btn hover:text-red-600" title="Remove contact" onClick={() => act(() => removeEmergency(g.id), 'Contact removed')}>
                  <Trash2 className="h-4 w-4" />
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div>
        <h3 className="mb-2 text-sm font-medium">People who trust me</h3>
        {data.trustedBy.length === 0 ? (
          <p className="text-sm text-slate-500">Nobody has named you an emergency contact.</p>
        ) : (
          <ul className="divide-y divide-slate-100 rounded-lg border border-slate-200 dark:divide-slate-800 dark:border-slate-800">
            {data.trustedBy.map((g) => (
              <li key={g.id} className="flex flex-wrap items-center gap-3 px-3 py-2.5">
                <HeartHandshake className="h-5 w-5 text-slate-400" />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm">{g.name ?? g.email}</div>
                  <div className="text-xs text-slate-500">
                    {g.status === 'accepted' && 'Waiting for them to confirm you'}
                    {g.status === 'confirmed' && `You can request access; it unlocks after ${g.waitDays} day(s) unless they reject it`}
                    {g.status === 'recovery_initiated' && `Requested · unlocks ${timeLeft(g.autoApproveAt)}`}
                    {g.status === 'recovery_approved' && 'Read-only access granted'}
                  </div>
                </div>
                {g.status === 'confirmed' && (
                  <button className="btn-secondary px-2.5 py-1 text-xs" disabled={busy} onClick={() => act(() => initiateEmergency(g.id), 'Access requested. They have been notified.')}>
                    <Clock className="h-3.5 w-3.5" /> Request access
                  </button>
                )}
                {g.status === 'recovery_approved' && (
                  <button className="btn-primary px-2.5 py-1 text-xs" onClick={() => navigate(`/emergency/${g.id}`)}>View vault</button>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>

      {inviting && (
        <Modal title="Add emergency contact" onClose={() => setInviting(false)}>
          <form onSubmit={invite} className="space-y-4">
            <div>
              <label className="label">Their e-mail</label>
              <input className="input" type="email" required autoFocus value={email} onChange={(e) => setEmail(e.target.value)} />
            </div>
            <div>
              <label className="label">Waiting period</label>
              <select className="input" value={waitDays} onChange={(e) => setWaitDays(Number(e.target.value))}>
                {[1, 2, 3, 7, 14, 30, 90].map((d) => <option key={d} value={d}>{d} day{d > 1 ? 's' : ''}</option>)}
              </select>
              <p className="mt-1 text-xs text-slate-500">
                When they request access, you're e-mailed and can reject it during this period. After it, they get read-only access to
                your personal vault (not organization items).
              </p>
            </div>
            <div className="flex justify-end gap-2">
              <button type="button" className="btn-secondary" onClick={() => setInviting(false)}>Cancel</button>
              <button className="btn-primary" disabled={busy || !email}>{busy && <Spinner />} Send invitation</button>
            </div>
          </form>
        </Modal>
      )}
      {confirming && (
        <Modal
          title={`Confirm ${confirming.name ?? confirming.email}`}
          onClose={() => setConfirming(null)}
          footer={
            <>
              <button className="btn-secondary" onClick={() => setConfirming(null)}>Cancel</button>
              <button
                className="btn-primary"
                disabled={busy}
                onClick={() => act(() => confirmEmergencyContact(confirming), 'Emergency contact confirmed').then(() => setConfirming(null))}
              >
                Confirm
              </button>
            </>
          }
        >
          <p className="text-sm text-slate-600 dark:text-slate-300">
            Your vault key will be sealed to this person's public key. Ask them to read the fingerprint in their <em>Settings → Account</em> and
            check it matches:
          </p>
          <div className="mt-3 flex items-center gap-2 rounded-lg bg-slate-50 p-3 dark:bg-slate-800/60">
            <Fingerprint className="h-5 w-5 text-slate-400" />
            <code className="font-mono text-sm">{confirming.publicKey ? publicKeyFingerprint(confirming.publicKey) : '—'}</code>
          </div>
        </Modal>
      )}
    </div>
  );
}
