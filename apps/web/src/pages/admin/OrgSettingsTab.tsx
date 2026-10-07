import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { InvalidPasswordError } from '@enclavier/crypto';
import { deleteOrganization, leaveOrganization, renameOrganization } from '../../lib/orgs';
import { useSession } from '../../lib/session';
import { Modal, PasswordInput, Spinner } from '../../components/ui';
import { errorMessage, toast } from '../../components/Toast';
import { useOrgData } from './shared';
import { RecoveryKitPanel } from './RecoveryKitPanel';

export function OrgSettingsTab() {
  const { orgId } = useOrgData();
  const org = useSession((s) => s.organizations.find((o) => o.id === orgId))!;
  const sync = useSession((s) => s.sync);
  const navigate = useNavigate();
  const [name, setName] = useState(org.name);
  const [busy, setBusy] = useState(false);
  const [dialog, setDialog] = useState<'leave' | 'delete' | null>(null);
  const [password, setPassword] = useState('');

  async function rename(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await renameOrganization(orgId, name.trim());
      await sync();
      toast('Organization renamed');
    } catch (err) {
      toast(errorMessage(err), 'error');
    } finally {
      setBusy(false);
    }
  }

  async function run(fn: () => Promise<void>, done: string) {
    setBusy(true);
    try {
      await fn();
      toast(done);
      navigate('/vault');
    } catch (err) {
      toast(err instanceof InvalidPasswordError ? 'Master password is incorrect' : errorMessage(err), 'error');
      setBusy(false);
    }
  }

  return (
    <div className="space-y-5">
      <section className="card p-5">
        <h2 className="font-semibold">General</h2>
        <form onSubmit={rename} className="mt-4 flex max-w-lg gap-2">
          <input className="input" maxLength={100} value={name} onChange={(e) => setName(e.target.value)} />
          <button className="btn-primary" disabled={busy || !name.trim() || name.trim() === org.name}>Save</button>
        </form>
        <p className="mt-2 text-xs text-slate-500">
          The organization name appears in invitation e-mails, so it is stored unencrypted. Collection names and items are encrypted.
        </p>
        <p className="mt-3 text-xs text-slate-500">
          Organization ID: <code className="rounded bg-slate-100 px-1.5 py-0.5 font-mono dark:bg-slate-800">{orgId}</code>
        </p>
      </section>

      <RecoveryKitPanel orgId={orgId} orgName={org.name} isOwner={org.role === 'owner'} />

      <section className="card border-red-200 p-5 dark:border-red-900/60">
        <h2 className="font-semibold text-red-700 dark:text-red-400">Danger zone</h2>
        <div className="mt-4 flex flex-wrap gap-2">
          <button className="btn-secondary" onClick={() => setDialog('leave')}>Leave organization</button>
          {org.role === 'owner' && (
            <button className="btn-danger" onClick={() => setDialog('delete')}>Delete organization</button>
          )}
        </div>
      </section>

      {dialog === 'leave' && (
        <Modal
          title={`Leave ${org.name}?`}
          onClose={() => setDialog(null)}
          footer={
            <>
              <button className="btn-secondary" onClick={() => setDialog(null)}>Cancel</button>
              <button className="btn-danger" disabled={busy} onClick={() => run(() => leaveOrganization(orgId), 'You left the organization')}>
                {busy && <Spinner />} Leave
              </button>
            </>
          }
        >
          <p className="text-sm text-slate-600 dark:text-slate-300">You will lose access to all of its collections. An admin must invite you again to rejoin.</p>
        </Modal>
      )}
      {dialog === 'delete' && (
        <Modal
          title={`Delete ${org.name}?`}
          onClose={() => setDialog(null)}
          footer={
            <>
              <button className="btn-secondary" onClick={() => setDialog(null)}>Cancel</button>
              <button className="btn-danger" disabled={busy || !password} onClick={() => run(() => deleteOrganization(orgId, password), 'Organization deleted')}>
                {busy && <Spinner />} Delete permanently
              </button>
            </>
          }
        >
          <div className="space-y-4">
            <p className="text-sm text-slate-600 dark:text-slate-300">
              Every collection, item, group and membership is erased for everyone. This cannot be undone.
            </p>
            <div>
              <label className="label">Confirm with your master password</label>
              <PasswordInput value={password} onChange={setPassword} autoFocus autoComplete="current-password" />
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
