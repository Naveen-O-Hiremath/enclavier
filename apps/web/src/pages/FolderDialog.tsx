import { useState, type FormEvent } from 'react';
import { useSession, type VaultFolder } from '../lib/session';
import { Modal, Spinner } from '../components/ui';
import { errorMessage, toast } from '../components/Toast';

export function FolderDialog(props: { folder?: VaultFolder; onClose: () => void; onSaved?: (id: string) => void }) {
  const saveFolder = useSession((s) => s.saveFolder);
  const [name, setName] = useState(props.folder?.name ?? '');
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    try {
      const before = new Set(useSession.getState().folders.map((f) => f.id));
      await saveFolder({ id: props.folder?.id, name: name.trim() });
      const created = useSession.getState().folders.find((f) => !before.has(f.id));
      toast(props.folder ? 'Folder renamed' : 'Folder created');
      props.onSaved?.(props.folder?.id ?? created?.id ?? '');
      props.onClose();
    } catch (err) {
      toast(errorMessage(err), 'error');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title={props.folder ? 'Rename folder' : 'New folder'} onClose={props.onClose}>
      <form onSubmit={submit} className="space-y-4">
        <div>
          <label className="label" htmlFor="folder-name">Name</label>
          <input id="folder-name" className="input" autoFocus value={name} onChange={(e) => setName(e.target.value)} maxLength={100} />
        </div>
        <div className="flex justify-end gap-2">
          <button type="button" className="btn-secondary" onClick={props.onClose}>Cancel</button>
          <button className="btn-primary" disabled={busy || !name.trim()}>
            {busy && <Spinner />} Save
          </button>
        </div>
      </form>
    </Modal>
  );
}
