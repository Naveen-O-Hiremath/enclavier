import { useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Archive,
  ArrowLeft,
  ChevronDown,
  Copy,
  CreditCard,
  ExternalLink,
  FileText,
  FolderPen,
  History,
  KeyRound,
  Pencil,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  ShieldAlert,
  Star,
  Trash2,
  UserSquare,
  Users,
} from 'lucide-react';
import { parseTotp, totpCode } from '@enclavier/crypto';
import { PERMISSION_RANK, type ItemType } from '@enclavier/shared';
import { useSession, type VaultItem } from '../lib/session';
import { copyWithToast, EmptyState, Modal, SecretRow, Spinner } from '../components/ui';
import { errorMessage, toast } from '../components/Toast';
import { ItemEditor, TYPE_LABELS } from './ItemEditor';
import { FolderDialog } from './FolderDialog';

const TYPE_ICON: Record<ItemType, typeof KeyRound> = { login: KeyRound, card: CreditCard, identity: UserSquare, note: FileText };

function subtitle(i: VaultItem): string {
  switch (i.data.type) {
    case 'login':
      return i.data.login?.username || i.data.login?.uris?.[0] || '';
    case 'card':
      return i.data.card?.number ? `${i.data.card.brand ?? 'Card'} •••• ${i.data.card.number.slice(-4)}` : i.data.card?.brand ?? '';
    case 'identity':
      return i.data.identity?.fullName || i.data.identity?.email || '';
    default:
      return (i.data.notes ?? '').split('\n')[0]!.slice(0, 80);
  }
}

function ItemAvatar({ item, size = 'md' }: { item: VaultItem; size?: 'md' | 'lg' }) {
  const Icon = TYPE_ICON[item.data.type];
  const box = size === 'lg' ? 'h-12 w-12 rounded-xl' : 'h-9 w-9 rounded-lg';
  const letter = item.data.name.trim().charAt(0).toUpperCase();
  return (
    <div className={`${box} flex shrink-0 items-center justify-center bg-slate-100 font-semibold text-slate-600 dark:bg-slate-800 dark:text-slate-300`}>
      {item.data.type === 'login' && letter ? <span className={size === 'lg' ? 'text-lg' : 'text-sm'}>{letter}</span> : <Icon className="h-4 w-4" />}
    </div>
  );
}

function TotpRow({ secret, masked }: { secret: string; masked?: boolean }) {
  const cfg = useMemo(() => {
    try {
      return parseTotp(secret);
    } catch {
      return null;
    }
  }, [secret]);
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  if (!cfg) return <div className="px-4 py-3 text-sm text-red-600">Invalid authenticator key</div>;
  if (masked) return <SecretRow label="Verification code" value="" masked />;
  const { code, remaining } = totpCode(cfg, now);
  const pct = (remaining / cfg.period) * 100;
  return (
    <div className="flex items-center gap-3 px-4 py-3">
      <div className="min-w-0 flex-1">
        <div className="text-xs text-slate-500">Verification code</div>
        <div className="font-mono text-lg tracking-widest text-brand-700 dark:text-brand-400">
          {code.slice(0, Math.ceil(code.length / 2))} {code.slice(Math.ceil(code.length / 2))}
        </div>
      </div>
      <div className="relative h-8 w-8" title={`${remaining}s remaining`}>
        <svg viewBox="0 0 36 36" className="h-8 w-8 -rotate-90">
          <circle cx="18" cy="18" r="15" fill="none" className="stroke-slate-200 dark:stroke-slate-700" strokeWidth="3" />
          <circle cx="18" cy="18" r="15" fill="none" className={remaining <= 5 ? 'stroke-red-500' : 'stroke-brand-500'} strokeWidth="3" strokeDasharray={`${(pct * 94.2) / 100} 94.2`} strokeLinecap="round" />
        </svg>
        <span className="absolute inset-0 flex items-center justify-center text-[10px] font-medium">{remaining}</span>
      </div>
      {!masked && (
        <button className="icon-btn" onClick={() => copyWithToast(code, 'Code')} aria-label="Copy code">
          <Copy className="h-4 w-4" />
        </button>
      )}
    </div>
  );
}

function Section({ title, children }: { title?: string; children: React.ReactNode }) {
  return (
    <div>
      {title && <div className="mb-1.5 px-1 text-xs font-medium tracking-wide text-slate-500 uppercase">{title}</div>}
      <div className="card divide-y divide-slate-100 overflow-hidden dark:divide-slate-800">{children}</div>
    </div>
  );
}

/** The first website of a login item that can be opened safely (http/https only). */
export function launchUrl(item: VaultItem): string | undefined {
  if (item.data.type !== 'login') return undefined;
  for (const uri of item.data.login?.uris ?? []) {
    const href = safeHref(uri);
    if (href) return href;
  }
  return undefined;
}

function safeHref(uri: string): string | undefined {
  const withScheme = /^[a-z][a-z0-9+.-]*:/i.test(uri) ? uri : `https://${uri}`;
  try {
    const u = new URL(withScheme);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : undefined;
  } catch {
    return undefined;
  }
}

function ItemDetail({ item, onBack, onEdit }: { item: VaultItem; onBack: () => void; onEdit: () => void }) {
  const { saveItem, trashItem, restoreItem, deleteItem, folders, collections, organizations } = useSession();
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [busy, setBusy] = useState(false);
  const d = item.data;
  const folder = folders.find((f) => f.id === item.folderId);
  const collection = collections.find((c) => c.id === item.collectionId);
  const org = organizations.find((o) => o.id === item.orgId);
  const canEdit = PERMISSION_RANK[item.permission] >= PERMISSION_RANK.edit;
  const canManage = item.permission === 'manage';
  const masked = item.permission === 'use';

  async function run(fn: () => Promise<unknown>, done: string) {
    setBusy(true);
    try {
      await fn();
      toast(done);
    } catch (e) {
      toast(errorMessage(e), 'error');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-1 border-b border-slate-200 px-4 py-2.5 dark:border-slate-800">
        <button className="icon-btn lg:hidden" onClick={onBack} aria-label="Back">
          <ArrowLeft className="h-4 w-4" />
        </button>
        <div className="flex-1" />
        {launchUrl(item) && !item.deletedAt && (
          <a className="btn-secondary mr-1" href={launchUrl(item)} target="_blank" rel="noopener noreferrer" title={`Open ${launchUrl(item)}`}>
            <ExternalLink className="h-4 w-4" /> Launch
          </a>
        )}
        {!canEdit ? (
          <span className="text-xs text-slate-500">{masked ? 'Use only' : 'View only'}</span>
        ) : item.deletedAt ? (
          <>
            <button className="btn-secondary" disabled={busy} onClick={() => run(() => restoreItem(item.id), 'Item restored')}>
              <RotateCcw className="h-4 w-4" /> Restore
            </button>
            {canManage && (
              <button className="btn-danger" disabled={busy} onClick={() => setConfirmDelete(true)}>
                <Trash2 className="h-4 w-4" /> Delete forever
              </button>
            )}
          </>
        ) : (
          <>
            <button
              className="icon-btn"
              disabled={busy}
              title={d.favorite ? 'Remove from favorites' : 'Add to favorites'}
              onClick={() =>
                run(
                  () => saveItem({ id: item.id, folderId: item.folderId, collectionId: item.collectionId, data: { ...d, favorite: !d.favorite } }),
                  d.favorite ? 'Removed from favorites' : 'Added to favorites',
                )
              }
            >
              <Star className={`h-4 w-4 ${d.favorite ? 'fill-amber-400 text-amber-400' : ''}`} />
            </button>
            <button className="icon-btn" disabled={busy} title="Move to trash" onClick={() => run(() => trashItem(item.id), 'Moved to trash')}>
              <Trash2 className="h-4 w-4" />
            </button>
            <button className="btn-primary ml-1" onClick={onEdit}>
              <Pencil className="h-4 w-4" /> Edit
            </button>
          </>
        )}
      </div>

      <div className="flex-1 space-y-5 overflow-y-auto p-5">
        <div className="flex items-center gap-4">
          <ItemAvatar item={item} size="lg" />
          <div className="min-w-0">
            <h2 className="truncate text-xl font-semibold">{d.name}</h2>
            <div className="flex flex-wrap items-center gap-x-1.5 text-sm text-slate-500">
              {TYPE_LABELS[d.type]}
              {folder ? ` · ${folder.name}` : ''}
              {org && (
                <span className="inline-flex items-center gap-1">
                  · <Users className="h-3.5 w-3.5" /> {org.name} / {collection?.name}
                </span>
              )}
              {item.deletedAt ? ' · In trash' : ''}
            </div>
          </div>
        </div>

        {d.type === 'login' && (d.login?.username || d.login?.password || d.login?.totp) && (
          <Section>
            {d.login?.username && <SecretRow label="Username" value={d.login.username} />}
            {d.login?.password && <SecretRow label="Password" value={d.login.password} secret masked={masked} />}
            {d.login?.totp && <TotpRow secret={d.login.totp} masked={masked} />}
          </Section>
        )}
        {d.type === 'login' && !!d.login?.uris?.length && (
          <Section title="Websites">
            {d.login.uris.map((u, i) => (
              <SecretRow key={i} label={`Website ${d.login!.uris!.length > 1 ? i + 1 : ''}`.trim()} value={u} href={safeHref(u)} />
            ))}
          </Section>
        )}
        {d.type === 'card' && (
          <Section>
            {d.card?.cardholder && <SecretRow label="Cardholder" value={d.card.cardholder} />}
            {d.card?.number && <SecretRow label="Number" value={d.card.number} secret masked={masked} />}
            {(d.card?.expMonth || d.card?.expYear) && <SecretRow label="Expires" value={`${d.card?.expMonth ?? '--'}/${d.card?.expYear ?? '----'}`} />}
            {d.card?.code && <SecretRow label="Security code" value={d.card.code} secret masked={masked} />}
          </Section>
        )}
        {d.type === 'identity' && (
          <Section>
            {d.identity?.fullName && <SecretRow label="Full name" value={d.identity.fullName} />}
            {d.identity?.company && <SecretRow label="Company" value={d.identity.company} />}
            {d.identity?.email && <SecretRow label="E-mail" value={d.identity.email} />}
            {d.identity?.phone && <SecretRow label="Phone" value={d.identity.phone} />}
            {d.identity?.address && <SecretRow label="Address" value={d.identity.address} />}
          </Section>
        )}
        {!!d.fields?.length && (
          <Section title="Custom fields">
            {d.fields.map((f, i) => (
              <SecretRow key={i} label={f.name || 'Field'} value={f.value} secret={f.hidden} masked={masked && f.hidden} />
            ))}
          </Section>
        )}
        {d.notes && (
          <Section title="Notes">
            <div className="px-4 py-3 text-sm whitespace-pre-wrap">{d.notes}</div>
          </Section>
        )}

        <div className="space-y-1 px-1 text-xs text-slate-500">
          <div>Updated {new Date(item.revisionDate).toLocaleString()}</div>
          <div>Created {new Date(item.createdAt).toLocaleString()}</div>
          {!!d.passwordHistory?.length && !masked && (
            <button className="inline-flex items-center gap-1 text-brand-600 hover:underline dark:text-brand-400" onClick={() => setShowHistory(true)}>
              <History className="h-3.5 w-3.5" /> Password history ({d.passwordHistory.length})
            </button>
          )}
        </div>
      </div>

      {confirmDelete && (
        <Modal
          title="Delete permanently?"
          onClose={() => setConfirmDelete(false)}
          footer={
            <>
              <button className="btn-secondary" onClick={() => setConfirmDelete(false)}>Cancel</button>
              <button
                className="btn-danger"
                disabled={busy}
                onClick={() => run(() => deleteItem(item.id), 'Item deleted').then(() => { setConfirmDelete(false); onBack(); })}
              >
                Delete forever
              </button>
            </>
          }
        >
          <p className="text-sm text-slate-600 dark:text-slate-300">
            “{d.name}” will be erased from the server. This cannot be undone.
          </p>
        </Modal>
      )}
      {showHistory && (
        <Modal title="Password history" onClose={() => setShowHistory(false)}>
          <div className="card divide-y divide-slate-100 dark:divide-slate-800">
            {d.passwordHistory!.map((h, i) => (
              <SecretRow key={i} label={new Date(h.changedAt).toLocaleString()} value={h.password} secret />
            ))}
          </div>
        </Modal>
      )}
    </div>
  );
}

function NewItemMenu({ onPick }: { onPick: (t: ItemType) => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const close = (e: MouseEvent) => ref.current && !ref.current.contains(e.target as Node) && setOpen(false);
    document.addEventListener('mousedown', close);
    return () => document.removeEventListener('mousedown', close);
  }, []);
  return (
    <div className="relative" ref={ref}>
      <button className="btn-primary" onClick={() => setOpen((o) => !o)}>
        <Plus className="h-4 w-4" /> New <ChevronDown className="h-3.5 w-3.5 opacity-70" />
      </button>
      {open && (
        <div className="card absolute right-0 z-20 mt-1 w-44 p-1 shadow-lg">
          {(Object.keys(TYPE_LABELS) as ItemType[]).map((t) => {
            const Icon = TYPE_ICON[t];
            return (
              <button key={t} className="flex w-full items-center gap-2 rounded-md px-2.5 py-1.5 text-left text-sm hover:bg-slate-100 dark:hover:bg-slate-800" onClick={() => { setOpen(false); onPick(t); }}>
                <Icon className="h-4 w-4 text-slate-500" /> {TYPE_LABELS[t]}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

export function VaultPage() {
  const { items, folders, collections, organizations, sync, syncing, corrupted, deleteFolder } = useSession();
  const [params, setParams] = useSearchParams();
  const [query, setQuery] = useState('');
  const [editor, setEditor] = useState<{ item?: VaultItem; type?: ItemType } | null>(null);
  const [folderEdit, setFolderEdit] = useState(false);
  const view = params.get('view') ?? 'all';
  const selectedId = params.get('item');
  const folderId = view.startsWith('folder:') ? view.slice(7) : null;
  const folder = folders.find((f) => f.id === folderId);
  const collectionId = view.startsWith('collection:') ? view.slice(11) : null;
  const collection = collections.find((c) => c.id === collectionId);
  const canCreateHere = !collection || PERMISSION_RANK[collection.permission] >= PERMISSION_RANK.edit;
  const orgName = (id: string | null) => organizations.find((o) => o.id === id)?.name;

  const select = (id: string | null) => {
    const next = new URLSearchParams(params);
    if (id) next.set('item', id);
    else next.delete('item');
    setParams(next, { replace: true });
  };

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return items
      .filter((i) => (view === 'trash' ? !!i.deletedAt : !i.deletedAt))
      .filter((i) => {
        if (view === 'favorites') return !!i.data.favorite;
        if (view.startsWith('type:')) return i.data.type === view.slice(5);
        if (folderId) return i.folderId === folderId;
        if (collectionId) return i.collectionId === collectionId;
        return true;
      })
      .filter((i) => {
        if (!q) return true;
        const hay = [i.data.name, i.data.login?.username, ...(i.data.login?.uris ?? []), i.data.notes, i.data.identity?.email, i.data.card?.cardholder]
          .filter(Boolean)
          .join(' ')
          .toLowerCase();
        return hay.includes(q);
      })
      .sort((a, b) => a.data.name.localeCompare(b.data.name, undefined, { sensitivity: 'base' }));
  }, [items, view, folderId, collectionId, query]);

  const selected = items.find((i) => i.id === selectedId) ?? null;
  const title =
    view === 'all' ? 'All items'
    : view === 'favorites' ? 'Favorites'
    : view === 'trash' ? 'Trash'
    : view.startsWith('type:') ? `${TYPE_LABELS[view.slice(5) as ItemType]}s`
    : collection ? collection.name
    : folder?.name ?? 'Folder';

  return (
    <div className="flex h-full">
      <section className={`${selected ? 'hidden lg:flex' : 'flex'} w-full flex-col border-r border-slate-200 lg:w-[400px] lg:shrink-0 dark:border-slate-800`}>
        <div className="space-y-3 border-b border-slate-200 p-4 dark:border-slate-800">
          <div className="flex items-center gap-2">
            <h1 className="flex min-w-0 flex-1 items-center gap-2 text-lg font-semibold">
              {collection && <Archive className="h-4 w-4 shrink-0 text-slate-400" />}
              <span className="truncate">{title}</span>
            </h1>
            {folder && (
              <>
                <button className="icon-btn" title="Rename folder" onClick={() => setFolderEdit(true)}><FolderPen className="h-4 w-4" /></button>
                <button
                  className="icon-btn"
                  title="Delete folder (items are kept)"
                  onClick={() => deleteFolder(folder.id).then(() => { toast('Folder deleted'); setParams({}); }, (e) => toast(errorMessage(e), 'error'))}
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </>
            )}
            <button className="icon-btn" title="Sync" onClick={() => sync().catch((e) => toast(errorMessage(e), 'error'))}>
              {syncing ? <Spinner /> : <RefreshCw className="h-4 w-4" />}
            </button>
            {view !== 'trash' && canCreateHere && <NewItemMenu onPick={(type) => setEditor({ type })} />}
          </div>
          <div className="relative">
            <Search className="absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-slate-400" />
            <input className="input pl-9" placeholder="Search vault" value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>
          {corrupted > 0 && (
            <div className="flex items-center gap-2 rounded-lg bg-red-50 px-3 py-2 text-xs text-red-700 dark:bg-red-950/40 dark:text-red-300">
              <ShieldAlert className="h-4 w-4 shrink-0" />
              {corrupted} item(s) failed integrity checks and are hidden.
            </div>
          )}
        </div>
        <div className="flex-1 overflow-y-auto">
          {visible.length === 0 ? (
            <EmptyState
              icon={view === 'trash' ? <Trash2 className="h-5 w-5" /> : <KeyRound className="h-5 w-5" />}
              title={query ? 'No matches' : view === 'trash' ? 'Trash is empty' : 'Nothing here yet'}
              hint={query ? 'Try a different search.' : view === 'trash' ? undefined : 'Add your first item — it is encrypted before it leaves this device.'}
            />
          ) : (
            <ul className="divide-y divide-slate-100 dark:divide-slate-800/70">
              {visible.map((i) => (
                <li key={i.id} className="relative">
                  <button
                    onClick={() => select(i.id)}
                    className={`flex w-full items-center gap-3 px-4 py-2.5 text-left transition ${launchUrl(i) && !i.deletedAt ? 'pr-12' : ''} ${
                      i.id === selectedId ? 'bg-brand-50 dark:bg-brand-500/10' : 'hover:bg-slate-50 dark:hover:bg-slate-900'
                    }`}
                  >
                    <ItemAvatar item={i} />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-1.5 truncate text-sm font-medium">
                        {i.data.name}
                        {i.data.favorite && <Star className="h-3 w-3 shrink-0 fill-amber-400 text-amber-400" />}
                      </div>
                      <div className="flex items-center gap-1.5 truncate text-xs text-slate-500">
                        {i.orgId && !collectionId && (
                          <span className="inline-flex shrink-0 items-center gap-0.5 rounded bg-slate-100 px-1 py-px text-[10px] font-medium text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                            <Users className="h-2.5 w-2.5" /> {orgName(i.orgId)}
                          </span>
                        )}
                        <span className="truncate">{subtitle(i)}</span>
                      </div>
                    </div>
                  </button>
                  {launchUrl(i) && !i.deletedAt && (
                    <a
                      href={launchUrl(i)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="icon-btn absolute top-1/2 right-3 -translate-y-1/2"
                      title={`Launch ${new URL(launchUrl(i)!).hostname}`}
                      aria-label={`Launch ${i.data.name}`}
                    >
                      <ExternalLink className="h-4 w-4" />
                    </a>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      <section className={`${selected ? 'flex' : 'hidden lg:flex'} min-w-0 flex-1 flex-col bg-slate-50 dark:bg-slate-950`}>
        {selected ? (
          <ItemDetail key={selected.id} item={selected} onBack={() => select(null)} onEdit={() => setEditor({ item: selected })} />
        ) : (
          <EmptyState icon={<KeyRound className="h-5 w-5" />} title="Select an item" hint="Choose an item from the list to see its details." />
        )}
      </section>

      {editor && (
        <ItemEditor
          item={editor.item}
          type={editor.type}
          defaultFolderId={folderId}
          defaultCollectionId={collection && canCreateHere ? collection.id : null}
          onClose={() => setEditor(null)}
          onSaved={(it) => select(it.id)}
        />
      )}
      {folderEdit && folder && <FolderDialog folder={folder} onClose={() => setFolderEdit(false)} />}
    </div>
  );
}
