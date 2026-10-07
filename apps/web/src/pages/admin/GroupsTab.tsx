import { useState } from 'react';
import { Pencil, Plus, Trash2, UsersRound } from 'lucide-react';
import type { OrgGroup } from '@enclavier/shared';
import { deleteGroup, saveGroup } from '../../lib/orgs';
import { EmptyState, Modal, Spinner } from '../../components/ui';
import { errorMessage, toast } from '../../components/Toast';
import { CheckList, fromGrantMap, GrantEditor, memberLabel, toGrantMap, useOrgData, type GrantMap } from './shared';

function GroupDialog({ group, onClose }: { group?: OrgGroup; onClose: () => void }) {
  const { orgId, members, collections, reload } = useOrgData();
  const [name, setName] = useState(group?.name ?? '');
  const [memberIds, setMemberIds] = useState<string[]>(group?.memberIds ?? []);
  const [externalId, setExternalId] = useState(group?.externalId ?? '');
  const [grants, setGrants] = useState<GrantMap>(toGrantMap(group?.collections ?? [], (c) => c.id, (c) => c.permission));
  const [busy, setBusy] = useState(false);

  async function save() {
    setBusy(true);
    try {
      await saveGroup(orgId, { id: group?.id, name: name.trim(), memberIds, collections: fromGrantMap(grants), externalId: externalId.trim() || null });
      toast(group ? 'Group updated' : 'Group created');
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
      title={group ? `Edit ${group.name}` : 'New group'}
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
          <input className="input" autoFocus maxLength={100} value={name} onChange={(e) => setName(e.target.value)} placeholder="Engineering" />
        </div>
        <div>
          <label className="label">Identity provider group (optional)</label>
          <input className="input font-mono text-xs" maxLength={200} value={externalId} onChange={(e) => setExternalId(e.target.value)} placeholder="Group ID or name in Okta / Entra ID" />
          <p className="mt-1 text-xs text-slate-500">When set, SCIM and SSO group sync manage who is in this group.</p>
        </div>
        <div>
          <label className="label">Members</label>
          <CheckList
            options={members.filter((m) => m.role === 'member').map((m) => ({ id: m.id, label: memberLabel(m), sublabel: m.email }))}
            value={memberIds}
            onChange={setMemberIds}
            empty="Invite members first. Owners and admins already see everything."
          />
        </div>
        <div>
          <label className="label">Collection access</label>
          <GrantEditor options={collections.map((c) => ({ id: c.id, label: c.name }))} value={grants} onChange={setGrants} empty="No collections yet." />
        </div>
      </div>
    </Modal>
  );
}

export function GroupsTab() {
  const { orgId, groups, collections, loading, reload } = useOrgData();
  const [editing, setEditing] = useState<OrgGroup | 'new' | null>(null);
  const [deleting, setDeleting] = useState<OrgGroup | null>(null);

  if (loading) return <Spinner className="h-6 w-6" />;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-slate-500">Groups grant collection access to many members at once.</p>
        <button className="btn-primary" onClick={() => setEditing('new')}><Plus className="h-4 w-4" /> New group</button>
      </div>
      {groups.length === 0 ? (
        <div className="card"><EmptyState icon={<UsersRound className="h-5 w-5" />} title="No groups yet" hint="Create groups such as Engineering or Finance." /></div>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2">
          {groups.map((g) => (
            <div key={g.id} className="card flex items-start gap-3 p-4">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-brand-50 text-brand-600 dark:bg-brand-500/10"><UsersRound className="h-4 w-4" /></div>
              <div className="min-w-0 flex-1">
                <div className="font-medium">
                  {g.name}
                  {g.externalId && <span className="ml-2 rounded bg-slate-100 px-1.5 py-0.5 text-[10px] font-semibold text-slate-600 uppercase dark:bg-slate-800 dark:text-slate-300">IdP-managed</span>}
                </div>
                <div className="text-xs text-slate-500">
                  {g.memberIds.length} member{g.memberIds.length === 1 ? '' : 's'} ·{' '}
                  {g.collections.map((c) => collections.find((x) => x.id === c.id)?.name).filter(Boolean).join(', ') || 'no collections'}
                </div>
              </div>
              <button className="icon-btn" title="Edit" onClick={() => setEditing(g)}><Pencil className="h-4 w-4" /></button>
              <button className="icon-btn hover:text-red-600" title="Delete" onClick={() => setDeleting(g)}><Trash2 className="h-4 w-4" /></button>
            </div>
          ))}
        </div>
      )}
      {editing && <GroupDialog group={editing === 'new' ? undefined : editing} onClose={() => setEditing(null)} />}
      {deleting && (
        <Modal
          title="Delete group?"
          onClose={() => setDeleting(null)}
          footer={
            <>
              <button className="btn-secondary" onClick={() => setDeleting(null)}>Cancel</button>
              <button
                className="btn-danger"
                onClick={() =>
                  deleteGroup(orgId, deleting.id).then(
                    () => { toast('Group deleted'); setDeleting(null); void reload(); },
                    (e) => toast(errorMessage(e), 'error'),
                  )
                }
              >
                Delete
              </button>
            </>
          }
        >
          <p className="text-sm text-slate-600 dark:text-slate-300">
            Members of “{deleting.name}” lose any access they had only through this group. The members themselves are not removed.
          </p>
        </Modal>
      )}
    </div>
  );
}
