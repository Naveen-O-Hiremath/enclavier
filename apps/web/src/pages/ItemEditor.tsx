import { useState, type FormEvent, type ReactNode } from 'react';
import { Plus, Trash2, Wand2 } from 'lucide-react';
import { generatePassword, parseTotp } from '@enclavier/crypto';
import { PERMISSION_RANK, type ItemData, type ItemType } from '@enclavier/shared';
import { useSession, type VaultItem } from '../lib/session';
import { Modal, PasswordInput, Spinner, StrengthMeter } from '../components/ui';
import { errorMessage, toast } from '../components/Toast';
import { loadGeneratorOptions } from './GeneratorPage';

export const TYPE_LABELS: Record<ItemType, string> = {
  login: 'Login',
  card: 'Card',
  identity: 'Identity',
  note: 'Secure note',
};

function blank(type: ItemType): ItemData {
  switch (type) {
    case 'login':
      return { type, name: '', login: { username: '', password: '', uris: [''], totp: '' } };
    case 'card':
      return { type, name: '', card: {} };
    case 'identity':
      return { type, name: '', identity: {} };
    default:
      return { type, name: '' };
  }
}

function Field({ label, children, className = '' }: { label: string; children: ReactNode; className?: string }) {
  return (
    <div className={className}>
      <label className="label">{label}</label>
      {children}
    </div>
  );
}

export function ItemEditor(props: {
  item?: VaultItem;
  type?: ItemType;
  defaultFolderId?: string | null;
  defaultCollectionId?: string | null;
  onClose: () => void;
  onSaved: (item: VaultItem) => void;
}) {
  const { saveItem, folders, organizations, collections } = useSession();
  const [collectionId, setCollectionId] = useState<string | null>(props.item?.collectionId ?? props.defaultCollectionId ?? null);
  // Writable destinations: personal vault (unless the item already belongs to an org) and collections we can edit.
  const writable = collections.filter(
    (c) => PERMISSION_RANK[c.permission] >= PERMISSION_RANK.edit && (!props.item?.orgId || c.orgId === props.item.orgId),
  );
  const movingIntoOrg = !!props.item && !props.item.orgId && !!collectionId;
  const [data, setData] = useState<ItemData>(() => (props.item ? structuredClone(props.item.data) : blank(props.type ?? 'login')));
  const [folderId, setFolderId] = useState<string | null>(props.item?.folderId ?? props.defaultFolderId ?? null);
  const [busy, setBusy] = useState(false);

  const set = (patch: Partial<ItemData>) => setData((d) => ({ ...d, ...patch }));
  const setLogin = (patch: Partial<NonNullable<ItemData['login']>>) => setData((d) => ({ ...d, login: { ...d.login, ...patch } }));
  const setCard = (patch: Partial<NonNullable<ItemData['card']>>) => setData((d) => ({ ...d, card: { ...d.card, ...patch } }));
  const setIdentity = (patch: Partial<NonNullable<ItemData['identity']>>) => setData((d) => ({ ...d, identity: { ...d.identity, ...patch } }));

  const uris = data.login?.uris?.length ? data.login.uris : [''];
  const fields = data.fields ?? [];

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!data.name.trim()) return toast('Give the item a name', 'error');
    if (data.login?.totp) {
      try {
        parseTotp(data.login.totp);
      } catch {
        return toast('The authenticator key is not a valid base32 secret or otpauth:// URI', 'error');
      }
    }
    const clean: ItemData = { ...data, name: data.name.trim() };
    if (clean.login) clean.login = { ...clean.login, uris: (clean.login.uris ?? []).map((u) => u.trim()).filter(Boolean) };
    clean.fields = fields.filter((f) => f.name.trim() || f.value);
    // Keep the last 10 passwords so a bad rotation can be rolled back.
    const oldPassword = props.item?.data.login?.password;
    if (oldPassword && oldPassword !== clean.login?.password) {
      clean.passwordHistory = [{ password: oldPassword, changedAt: new Date().toISOString() }, ...(props.item?.data.passwordHistory ?? [])].slice(0, 10);
    }
    setBusy(true);
    try {
      const saved = await saveItem({ id: props.item?.id, folderId: collectionId ? null : folderId, collectionId, data: clean });
      toast(props.item ? 'Item saved' : 'Item created');
      props.onSaved(saved);
      props.onClose();
    } catch (err) {
      toast(errorMessage(err), 'error');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      wide
      title={`${props.item ? 'Edit' : 'New'} ${TYPE_LABELS[data.type].toLowerCase()}`}
      onClose={props.onClose}
      footer={
        <>
          <button type="button" className="btn-secondary" onClick={props.onClose}>Cancel</button>
          <button type="submit" form="item-form" className="btn-primary" disabled={busy}>
            {busy && <Spinner />} Save
          </button>
        </>
      }
    >
      <form id="item-form" onSubmit={submit} className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Name">
            <input className="input" autoFocus value={data.name} onChange={(e) => set({ name: e.target.value })} maxLength={200} />
          </Field>
          {(organizations.length > 0 || props.item?.orgId) && (
            <Field label="Owner">
              <select className="input" value={collectionId ?? ''} onChange={(e) => setCollectionId(e.target.value || null)}>
                {!props.item?.orgId && <option value="">My vault (private)</option>}
                {organizations
                  .filter((o) => writable.some((c) => c.orgId === o.id))
                  .map((o) => (
                    <optgroup key={o.id} label={o.name}>
                      {writable
                        .filter((c) => c.orgId === o.id)
                        .map((c) => (
                          <option key={c.id} value={c.id}>{c.name}</option>
                        ))}
                    </optgroup>
                  ))}
              </select>
            </Field>
          )}
          {!collectionId && (
            <Field label="Folder">
              <select className="input" value={folderId ?? ''} onChange={(e) => setFolderId(e.target.value || null)}>
                <option value="">No folder</option>
                {folders.map((f) => (
                  <option key={f.id} value={f.id}>{f.name}</option>
                ))}
              </select>
            </Field>
          )}
        </div>
        {movingIntoOrg && (
          <p className="rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:bg-amber-950/40 dark:text-amber-200">
            Saving moves this item into the organization. Everyone with access to the collection will see it, and it can't be moved back
            to your private vault.
          </p>
        )}

        {data.type === 'login' && (
          <>
            <Field label="Username">
              <input className="input" value={data.login?.username ?? ''} onChange={(e) => setLogin({ username: e.target.value })} autoComplete="off" />
            </Field>
            <Field label="Password">
              <div className="flex gap-2">
                <div className="flex-1">
                  <PasswordInput mono value={data.login?.password ?? ''} onChange={(v) => setLogin({ password: v })} />
                </div>
                <button type="button" className="btn-secondary" title="Generate" onClick={() => setLogin({ password: generatePassword(loadGeneratorOptions()) })}>
                  <Wand2 className="h-4 w-4" />
                </button>
              </div>
              <StrengthMeter password={data.login?.password ?? ''} />
            </Field>
            <Field label="Authenticator key (TOTP)">
              <input className="input font-mono" placeholder="Base32 secret or otpauth:// URI" value={data.login?.totp ?? ''} onChange={(e) => setLogin({ totp: e.target.value })} autoComplete="off" spellCheck={false} />
            </Field>
            <Field label="Websites">
              <div className="space-y-2">
                {uris.map((u, i) => (
                  <div key={i} className="flex gap-2">
                    <input className="input" placeholder="https://example.com" value={u} onChange={(e) => setLogin({ uris: uris.map((x, j) => (j === i ? e.target.value : x)) })} />
                    {uris.length > 1 && (
                      <button type="button" className="icon-btn mt-1" onClick={() => setLogin({ uris: uris.filter((_, j) => j !== i) })} aria-label="Remove website">
                        <Trash2 className="h-4 w-4" />
                      </button>
                    )}
                  </div>
                ))}
                <button type="button" className="btn-ghost px-2 py-1 text-xs" onClick={() => setLogin({ uris: [...uris, ''] })}>
                  <Plus className="h-3.5 w-3.5" /> Add website
                </button>
              </div>
            </Field>
          </>
        )}

        {data.type === 'card' && (
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Cardholder name"><input className="input" value={data.card?.cardholder ?? ''} onChange={(e) => setCard({ cardholder: e.target.value })} /></Field>
            <Field label="Brand"><input className="input" placeholder="Visa, Mastercard…" value={data.card?.brand ?? ''} onChange={(e) => setCard({ brand: e.target.value })} /></Field>
            <Field label="Number" className="sm:col-span-2"><PasswordInput mono value={data.card?.number ?? ''} onChange={(v) => setCard({ number: v })} /></Field>
            <div className="grid grid-cols-2 gap-4">
              <Field label="Exp. month"><input className="input" placeholder="MM" maxLength={2} value={data.card?.expMonth ?? ''} onChange={(e) => setCard({ expMonth: e.target.value })} /></Field>
              <Field label="Exp. year"><input className="input" placeholder="YYYY" maxLength={4} value={data.card?.expYear ?? ''} onChange={(e) => setCard({ expYear: e.target.value })} /></Field>
            </div>
            <Field label="Security code"><PasswordInput mono value={data.card?.code ?? ''} onChange={(v) => setCard({ code: v })} /></Field>
          </div>
        )}

        {data.type === 'identity' && (
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Full name"><input className="input" value={data.identity?.fullName ?? ''} onChange={(e) => setIdentity({ fullName: e.target.value })} /></Field>
            <Field label="Company"><input className="input" value={data.identity?.company ?? ''} onChange={(e) => setIdentity({ company: e.target.value })} /></Field>
            <Field label="E-mail"><input className="input" type="email" value={data.identity?.email ?? ''} onChange={(e) => setIdentity({ email: e.target.value })} /></Field>
            <Field label="Phone"><input className="input" value={data.identity?.phone ?? ''} onChange={(e) => setIdentity({ phone: e.target.value })} /></Field>
            <Field label="Address" className="sm:col-span-2"><textarea className="input min-h-20" value={data.identity?.address ?? ''} onChange={(e) => setIdentity({ address: e.target.value })} /></Field>
          </div>
        )}

        <Field label="Notes">
          <textarea className="input min-h-24" value={data.notes ?? ''} onChange={(e) => set({ notes: e.target.value })} />
        </Field>

        <Field label="Custom fields">
          <div className="space-y-2">
            {fields.map((f, i) => (
              <div key={i} className="flex gap-2">
                <input className="input w-2/5" placeholder="Name" value={f.name} onChange={(e) => set({ fields: fields.map((x, j) => (j === i ? { ...x, name: e.target.value } : x)) })} />
                <div className="flex-1">
                  {f.hidden ? (
                    <PasswordInput mono value={f.value} onChange={(v) => set({ fields: fields.map((x, j) => (j === i ? { ...x, value: v } : x)) })} />
                  ) : (
                    <input className="input" placeholder="Value" value={f.value} onChange={(e) => set({ fields: fields.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)) })} />
                  )}
                </div>
                <label className="flex items-center gap-1 text-xs text-slate-500" title="Hide value">
                  <input type="checkbox" checked={f.hidden} onChange={(e) => set({ fields: fields.map((x, j) => (j === i ? { ...x, hidden: e.target.checked } : x)) })} />
                  Hidden
                </label>
                <button type="button" className="icon-btn mt-1" onClick={() => set({ fields: fields.filter((_, j) => j !== i) })} aria-label="Remove field">
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            ))}
            <button type="button" className="btn-ghost px-2 py-1 text-xs" onClick={() => set({ fields: [...fields, { name: '', value: '', hidden: false }] })}>
              <Plus className="h-3.5 w-3.5" /> Add field
            </button>
          </div>
        </Field>

        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={!!data.favorite} onChange={(e) => set({ favorite: e.target.checked })} />
          Favorite
        </label>
      </form>
    </Modal>
  );
}
