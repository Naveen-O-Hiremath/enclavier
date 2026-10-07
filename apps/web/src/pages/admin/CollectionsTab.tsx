import { useState } from 'react';
import { Archive, Pencil, Plus, Trash2 } from 'lucide-react';
import { deleteCollection, saveCollection, type AdminCollection } from '../../lib/orgs';
import { EmptyState, Modal, Spinner } from '../../components/ui';
import { errorMessage, toast } from '../../components/Toast';
import { GrantEditor, memberLabel, toGrantMap, fromGrantMap, useOrgData, type GrantMap } from './shared';

function CollectionDialog({ collection, onClose }: { collection?: AdminCollection; onClose: () => void }) {
  const { orgId, members, groups, reload } = useOrgData();
  const [name, setName] = useState(collection?.name ?? '');
  const [memberGrants, setMemberGrants] = useState<GrantMap>(toGrantMap(collection?.members ?? [], (m) => m.memberId, (m) => m.permission));
  const [groupGrants, setGroupGrants] = useState<GrantMap>(toGrantMap(collection?.groups ?? [], (g) => g.groupId, (g) => g.permission));
  const [busy, setBusy] = useState(false);

  async function save() {
    setBusy(true);
    try {
      await saveCollection(orgId, {
        id: collection?.id,
        name: name.trim(),
        members: fromGrantMap(memberGrants).map((g) => ({ memberId: g.id, permission: g.permission })),
        groups: fromGrantMap(groupGrants).map((g) => ({ groupId: g.id, permission: g.permission })),
      });
      toast(collection ? 'Collection updated' : 'Collection created');
      await reload();
      onClose();
    } catch (err) {
      toast(errorMessage(err), 'error');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      wide
      title={collection ? `Edit ${collection.name}` : 'New collection'}
      onClose={onClose}
      footer={
        <>
          <button className="btn-secondary" onClick={onClose}>Cancel</button>
          <button className="btn-primary" onClick={save} disabled={busy || !name.trim()}>{busy && <Spinner />} Save</button>
        </>
      }
    >
      <div className="space-y-5">
        <div>
          <label className="label">Name</label>
          <input className="input" autoFocus maxLength={200} value={name} onChange={(e) => setName(e.target.value)} placeholder="Production databases" />
          <p className="mt-1 text-xs text-slate-500">Encrypted with the organization key: the server cannot read collection names.</p>
        </div>
        <div>
          <label className="label">Groups</label>
          <GrantEditor options={groups.map((g) => ({ id: g.id, label: g.name, sublabel: `${g.memberIds.length} members` }))} value={groupGrants} onChange={setGroupGrants} empty="No groups yet." />
        </div>
        <div>
          <label className="label">Individual members</label>
          <GrantEditor
            options={members.filter((m) => m.role === 'member').map((m) => ({ id: m.id, label: memberLabel(m), sublabel: m.email }))}
            value={memberGrants}
            onChange={setMemberGrants}
            empty="No members with the Member role. Owners and admins can access every collection."
          />
        </div>
      </div>
    </Modal>
  );
}

export function CollectionsTab() {
  const { orgId, collections, loading, reload } = useOrgData();
  const [editing, setEditing] = useState<AdminCollection | 'new' | null>(null);
  const [deleting, setDeleting] = useState<AdminCollection | null>(null);
  const [busy, setBusy] = useState(false);

  if (loading) return <Spinner className="h-6 w-6" />;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-slate-500">Collections hold shared items. Access is granted per member or group.</p>
        <button className="btn-primary" onClick={() => setEditing('new')}><Plus className="h-4 w-4" /> New collection</button>
      </div>
      {collections.length === 0 ? (
        <div className="card"><EmptyState icon={<Archive className="h-5 w-5" />} title="No collections" /></div>
      ) : (
        <div className="card divide-y divide-slate-100 dark:divide-slate-800">
          {collections.map((c) => (
            <div key={c.id} className="flex items-center gap-3 px-4 py-3">
              <Archive className="h-5 w-5 text-slate-400" />
              <div className="min-w-0 flex-1">
                <div className="truncate font-medium">{c.name}</div>
                <div className="text-xs text-slate-500">
                  {c.itemCount} item{c.itemCount === 1 ? '' : 's'} · {c.groups.length} group{c.groups.length === 1 ? '' : 's'} · {c.members.length} member
                  {c.members.length === 1 ? '' : 's'}
                </div>
              </div>
              <button className="icon-btn" title="Edit" onClick={() => setEditing(c)}><Pencil className="h-4 w-4" /></button>
              <button className="icon-btn hover:text-red-600" title="Delete" onClick={() => setDeleting(c)}><Trash2 className="h-4 w-4" /></button>
            </div>
          ))}
        </div>
      )}
      {editing && <CollectionDialog collection={editing === 'new' ? undefined : editing} onClose={() => setEditing(null)} />}
      {deleting && (
        <Modal
          title="Delete collection?"
          onClose={() => setDeleting(null)}
          footer={
            <>
              <button className="btn-secondary" onClick={() => setDeleting(null)}>Cancel</button>
              <button
                className="btn-danger"
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  try {
                    await deleteCollection(orgId, deleting.id);
                    toast('Collection deleted');
                    setDeleting(null);
                    await reload();
                  } catch (e) {
                    toast(errorMessage(e), 'error');
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                {busy && <Spinner />} Delete collection and {deleting.itemCount} item{deleting.itemCount === 1 ? '' : 's'}
              </button>
            </>
          }
        >
          <p className="text-sm text-slate-600 dark:text-slate-300">
            “{deleting.name}” and every item in it will be permanently erased for all members. This cannot be undone.
          </p>
        </Modal>
      )}
    </div>
  );
}
