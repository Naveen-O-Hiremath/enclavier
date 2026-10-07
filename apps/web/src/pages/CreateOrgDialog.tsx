import { useState, type FormEvent } from 'react';
import { KeyRound } from 'lucide-react';
import { createOrganization } from '../lib/orgs';
import { Modal, Spinner } from '../components/ui';
import { errorMessage, toast } from '../components/Toast';

export function CreateOrgDialog(props: { onClose: () => void; onCreated: (orgId: string) => void }) {
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const id = await createOrganization(name.trim());
      toast('Organization created');
      props.onCreated(id);
      props.onClose();
    } catch (err) {
      toast(errorMessage(err), 'error');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title="New organization" onClose={props.onClose}>
      <form onSubmit={submit} className="space-y-4">
        <div>
          <label className="label" htmlFor="org-name">Organization name</label>
          <input id="org-name" className="input" autoFocus maxLength={100} value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Corp" />
        </div>
        <div className="flex gap-2.5 rounded-lg bg-brand-50 p-3 text-xs text-brand-700 dark:bg-brand-500/10 dark:text-brand-400">
          <KeyRound className="mt-0.5 h-4 w-4 shrink-0" />
          A new organization key is generated on this device. Members receive it sealed to their own public key, so the server
          never sees it.
        </div>
        <div className="flex justify-end gap-2">
          <button type="button" className="btn-secondary" onClick={props.onClose}>Cancel</button>
          <button className="btn-primary" disabled={busy || !name.trim()}>
            {busy && <Spinner />} Create organization
          </button>
        </div>
      </form>
    </Modal>
  );
}
