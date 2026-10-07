import { useState, type FormEvent } from 'react';
import { Ban, CheckCircle2, Fingerprint, LifeBuoy, Mail, Pencil, RotateCcw, Trash2, UserPlus } from 'lucide-react';
import { generatePassword, publicKeyFingerprint } from '@enclavier/crypto';
import { recoverMemberAccount } from '../../lib/security';
import type { OrgMember, OrgRole } from '@enclavier/shared';
import { confirmMember, inviteMembers, reinviteMember, removeMember, ROLE_LABELS, setMemberRevoked, updateMember } from '../../lib/orgs';
import { useSession } from '../../lib/session';
import { copyWithToast, EmptyState, Modal, Spinner } from '../../components/ui';
import { errorMessage, toast } from '../../components/Toast';
import { Badge, CheckList, fromGrantMap, GrantEditor, memberLabel, RolePicker, toGrantMap, useOrgData, type GrantMap } from './shared';

function StatusBadge({ m }: { m: OrgMember }) {
  if (m.revoked) return <Badge tone="red">Revoked</Badge>;
  if (m.status === 'invited') {
    const expired = m.inviteExpiresAt && new Date(m.inviteExpiresAt) < new Date();
    return <Badge tone={expired ? 'red' : 'slate'}>{expired ? 'Invite expired' : 'Invited'}</Badge>;
  }
  if (m.status === 'accepted') return <Badge tone="amber">Needs confirmation</Badge>;
  return <Badge tone="green">Active</Badge>;
}

function useMyRole(orgId: string): { role: OrgRole; memberId: string } {
  const org = useSession((s) => s.organizations.find((o) => o.id === orgId))!;
  return { role: org.role, memberId: org.memberId };
}

function InviteDialog({ onClose }: { onClose: () => void }) {
  const { orgId, groups, collections, reload } = useOrgData();
  const { role: myRole } = useMyRole(orgId);
  const [emails, setEmails] = useState('');
  const [role, setRole] = useState<OrgRole>('member');
  const [groupIds, setGroupIds] = useState<string[]>([]);
  const [grants, setGrants] = useState<GrantMap>({});
  const [busy, setBusy] = useState(false);

  const parsed = [...new Set(emails.split(/[\s,;]+/).map((e) => e.trim().toLowerCase()).filter(Boolean))];
  const invalid = parsed.filter((e) => !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e));

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!parsed.length || invalid.length) return;
    setBusy(true);
    try {
      const res = await inviteMembers(orgId, { emails: parsed, role, groups: groupIds, collections: fromGrantMap(grants) });
      toast(
        res.skipped.length
          ? `Invited ${res.invited.length}. Skipped ${res.skipped.length} already in the organization.`
          : `Invitation${res.invited.length === 1 ? '' : 's'} sent to ${res.invited.length} ${res.invited.length === 1 ? 'person' : 'people'}`,
      );
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
      title="Invite members"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn-secondary" onClick={onClose}>Cancel</button>
          <button type="submit" form="invite-form" className="btn-primary" disabled={busy || !parsed.length || invalid.length > 0}>
            {busy && <Spinner />} Send {parsed.length > 1 ? `${parsed.length} invitations` : 'invitation'}
          </button>
        </>
      }
    >
      <form id="invite-form" onSubmit={submit} className="space-y-5">
        <div>
          <label className="label">E-mail addresses</label>
          <textarea
            className="input min-h-20"
            autoFocus
            placeholder="jane@company.com, raj@company.com"
            value={emails}
            onChange={(e) => setEmails(e.target.value)}
          />
          <p className={`mt-1 text-xs ${invalid.length ? 'text-red-600' : 'text-slate-500'}`}>
            {invalid.length ? `Invalid: ${invalid.join(', ')}` : 'Separate several addresses with commas or new lines (up to 50).'}
          </p>
        </div>
        <div>
          <label className="label">Role</label>
          <RolePicker value={role} onChange={setRole} allowOwner={myRole === 'owner'} />
        </div>
        {role === 'member' && (
          <>
            <div>
              <label className="label">Groups</label>
              <CheckList options={groups.map((g) => ({ id: g.id, label: g.name, sublabel: `${g.memberIds.length} members` }))} value={groupIds} onChange={setGroupIds} empty="No groups yet." />
            </div>
            <div>
              <label className="label">Direct collection access</label>
              <GrantEditor options={collections.map((c) => ({ id: c.id, label: c.name }))} value={grants} onChange={setGrants} empty="No collections yet." />
            </div>
          </>
        )}
      </form>
    </Modal>
  );
}

function EditMemberDialog({ member, onClose }: { member: OrgMember; onClose: () => void }) {
  const { orgId, groups, collections, reload } = useOrgData();
  const { role: myRole } = useMyRole(orgId);
  const [role, setRole] = useState<OrgRole>(member.role);
  const [groupIds, setGroupIds] = useState<string[]>(member.groups);
  const [grants, setGrants] = useState<GrantMap>(toGrantMap(member.collections, (c) => c.id, (c) => c.permission));
  const [busy, setBusy] = useState(false);

  async function save() {
    setBusy(true);
    try {
      await updateMember(orgId, member.id, { role, groups: groupIds, collections: fromGrantMap(grants) });
      toast('Member updated');
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
      title={`Edit ${memberLabel(member)}`}
      onClose={onClose}
      footer={
        <>
          <button className="btn-secondary" onClick={onClose}>Cancel</button>
          <button className="btn-primary" onClick={save} disabled={busy}>{busy && <Spinner />} Save</button>
        </>
      }
    >
      <div className="space-y-5">
        <div>
          <label className="label">Role</label>
          <RolePicker value={role} onChange={setRole} allowOwner={myRole === 'owner'} />
        </div>
        {role === 'member' ? (
          <>
            <div>
              <label className="label">Groups</label>
              <CheckList options={groups.map((g) => ({ id: g.id, label: g.name }))} value={groupIds} onChange={setGroupIds} empty="No groups yet." />
            </div>
            <div>
              <label className="label">Direct collection access</label>
              <GrantEditor options={collections.map((c) => ({ id: c.id, label: c.name }))} value={grants} onChange={setGrants} empty="No collections yet." />
            </div>
          </>
        ) : (
          <p className="rounded-lg bg-slate-50 p-3 text-sm text-slate-600 dark:bg-slate-800/50 dark:text-slate-300">
            {ROLE_LABELS[role].label}s can access and manage every collection.
          </p>
        )}
      </div>
    </Modal>
  );
}

/** Confirmation seals the org key to this member. Comparing fingerprints defeats a server that swaps in its own public key. */
function ConfirmDialog({ members, onClose }: { members: OrgMember[]; onClose: () => void }) {
  const { orgId, reload } = useOrgData();
  const [busy, setBusy] = useState(false);

  async function confirmAll() {
    setBusy(true);
    let ok = 0;
    for (const m of members) {
      try {
        await confirmMember(orgId, m);
        ok++;
      } catch (err) {
        toast(`${m.email}: ${errorMessage(err)}`, 'error');
      }
    }
    if (ok) toast(`Confirmed ${ok} member${ok === 1 ? '' : 's'}`);
    await reload();
    setBusy(false);
    onClose();
  }

  return (
    <Modal
      wide
      title={members.length === 1 ? `Confirm ${memberLabel(members[0]!)}` : `Confirm ${members.length} members`}
      onClose={onClose}
      footer={
        <>
          <button className="btn-secondary" onClick={onClose}>Cancel</button>
          <button className="btn-primary" onClick={confirmAll} disabled={busy}>
            {busy ? <Spinner /> : <CheckCircle2 className="h-4 w-4" />} Confirm
          </button>
        </>
      }
    >
      <p className="mb-4 text-sm text-slate-600 dark:text-slate-300">
        Confirming shares the organization key with {members.length === 1 ? 'this member' : 'these members'}. For high-assurance
        setups, ask each person to read out the fingerprint shown in <em>Settings → Account</em> and check it matches.
      </p>
      <div className="divide-y divide-slate-100 rounded-lg border border-slate-200 dark:divide-slate-800 dark:border-slate-800">
        {members.map((m) => (
          <div key={m.id} className="flex items-center gap-3 px-4 py-3">
            <Fingerprint className="h-5 w-5 text-slate-400" />
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm font-medium">{memberLabel(m)}</div>
              <div className="truncate text-xs text-slate-500">{m.email}</div>
            </div>
            <code className="rounded bg-slate-100 px-2 py-1 font-mono text-xs dark:bg-slate-800">
              {m.publicKey ? publicKeyFingerprint(m.publicKey) : '—'}
            </code>
          </div>
        ))}
      </div>
    </Modal>
  );
}

function RecoverDialog({ member, onClose }: { member: OrgMember; onClose: () => void }) {
  const { orgId, reload } = useOrgData();
  const [temp] = useState(() => generatePassword({ length: 20, lowercase: true, uppercase: true, digits: true, symbols: false, avoidAmbiguous: true }));
  const [step, setStep] = useState<'confirm' | 'done'>('confirm');
  const [busy, setBusy] = useState(false);

  async function recover() {
    setBusy(true);
    try {
      await recoverMemberAccount(orgId, member.id, temp);
      setStep('done');
      await reload();
    } catch (err) {
      toast(errorMessage(err), 'error');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title={step === 'confirm' ? `Reset master password for ${memberLabel(member)}?` : 'Temporary password'}
      onClose={onClose}
      footer={
        step === 'confirm' ? (
          <>
            <button className="btn-secondary" onClick={onClose}>Cancel</button>
            <button className="btn-danger" onClick={recover} disabled={busy}>{busy && <Spinner />} Reset password</button>
          </>
        ) : (
          <button className="btn-primary" onClick={onClose}>Done</button>
        )
      }
    >
      {step === 'confirm' ? (
        <div className="space-y-3 text-sm text-slate-600 dark:text-slate-300">
          <p>
            Your browser unseals {memberLabel(member)}'s vault key with the organization recovery key and re-encrypts it under a new temporary
            password. Their devices are signed out and they are e-mailed.
          </p>
          <p>Only do this after verifying their identity through a separate channel (phone, video, in person).</p>
        </div>
      ) : (
        <div className="space-y-3 text-sm">
          <p className="text-slate-600 dark:text-slate-300">
            Give this password to {memberLabel(member)} through a secure channel. They must replace it when they sign in. Their two-step login
            still applies.
          </p>
          <div className="flex items-center gap-2 rounded-lg bg-slate-50 p-3 dark:bg-slate-800/60">
            <code className="flex-1 font-mono text-base">{temp}</code>
            <button className="btn-secondary px-2.5 py-1 text-xs" onClick={() => copyWithToast(temp, 'Temporary password')}>Copy</button>
          </div>
        </div>
      )}
    </Modal>
  );
}

function RemoveDialog({ member, onClose }: { member: OrgMember; onClose: () => void }) {
  const { orgId, reload } = useOrgData();
  const [busy, setBusy] = useState(false);
  async function remove() {
    setBusy(true);
    try {
      await removeMember(orgId, member.id);
      toast('Member removed');
      await reload();
      onClose();
    } catch (err) {
      toast(errorMessage(err), 'error');
      setBusy(false);
    }
  }
  return (
    <Modal
      title="Remove member?"
      onClose={onClose}
      footer={
        <>
          <button className="btn-secondary" onClick={onClose}>Cancel</button>
          <button className="btn-danger" onClick={remove} disabled={busy}>{busy && <Spinner />} Remove</button>
        </>
      }
    >
      <p className="text-sm text-slate-600 dark:text-slate-300">
        {memberLabel(member)} loses access to every collection immediately. Anything they already viewed may have been copied, so
        rotate sensitive credentials they could see. To pause access instead, use <strong>Revoke</strong>.
      </p>
    </Modal>
  );
}

export function MembersTab() {
  const { orgId, members, groups, loading, reload } = useOrgData();
  const { role: myRole, memberId: myId } = useMyRole(orgId);
  const recoveryOn = useSession((s) => s.organizations.find((o) => o.id === orgId)?.policies.accountRecovery ?? false);
  const [dialog, setDialog] = useState<
    | { kind: 'invite' }
    | { kind: 'edit'; member: OrgMember }
    | { kind: 'confirm'; members: OrgMember[] }
    | { kind: 'remove'; member: OrgMember }
    | { kind: 'recover'; member: OrgMember }
    | null
  >(null);
  const [filter, setFilter] = useState('');

  const pending = members.filter((m) => m.status === 'accepted' && !m.revoked);
  const groupName = (id: string) => groups.find((g) => g.id === id)?.name;
  const canManage = (m: OrgMember) => m.id !== myId && (m.role !== 'owner' || myRole === 'owner');
  const visible = members.filter((m) => `${m.email} ${m.name ?? ''}`.toLowerCase().includes(filter.toLowerCase()));

  async function act(fn: () => Promise<unknown>, done: string) {
    try {
      await fn();
      toast(done);
      await reload();
    } catch (err) {
      toast(errorMessage(err), 'error');
    }
  }

  if (loading) return <Spinner className="h-6 w-6" />;

  return (
    <div className="space-y-4">
      {pending.length > 0 && (
        <div className="flex flex-wrap items-center gap-3 rounded-xl border border-amber-200 bg-amber-50 p-4 dark:border-amber-900/50 dark:bg-amber-950/30">
          <Fingerprint className="h-5 w-5 text-amber-600" />
          <div className="flex-1 text-sm text-amber-900 dark:text-amber-200">
            <strong>{pending.length}</strong> member{pending.length === 1 ? ' has' : 's have'} accepted and {pending.length === 1 ? 'is' : 'are'} waiting for
            you to share the organization key.
          </div>
          <button className="btn-primary" onClick={() => setDialog({ kind: 'confirm', members: pending })}>Review & confirm</button>
        </div>
      )}

      <div className="flex items-center gap-3">
        <input className="input max-w-xs" placeholder="Search members" value={filter} onChange={(e) => setFilter(e.target.value)} />
        <div className="flex-1" />
        <button className="btn-primary" onClick={() => setDialog({ kind: 'invite' })}>
          <UserPlus className="h-4 w-4" /> Invite members
        </button>
      </div>

      {members.length === 0 ? (
        <EmptyState icon={<UserPlus className="h-5 w-5" />} title="No members yet" />
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[640px] text-sm">
            <thead className="border-b border-slate-200 text-left text-xs text-slate-500 uppercase dark:border-slate-800">
              <tr>
                <th className="px-4 py-2.5 font-medium">Member</th>
                <th className="px-4 py-2.5 font-medium">Role</th>
                <th className="px-4 py-2.5 font-medium">Status</th>
                <th className="px-4 py-2.5 font-medium">Access</th>
                <th className="px-4 py-2.5" />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {visible.map((m) => (
                <tr key={m.id} className={m.revoked ? 'opacity-60' : ''}>
                  <td className="px-4 py-3">
                    <div className="font-medium">
                      {memberLabel(m)} {m.id === myId && <span className="text-xs font-normal text-slate-400">(you)</span>}
                    </div>
                    {m.name && <div className="text-xs text-slate-500">{m.email}</div>}
                  </td>
                  <td className="px-4 py-3">{ROLE_LABELS[m.role].label}</td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      <StatusBadge m={m} />
                      {m.status === 'confirmed' && !m.twoFactorEnabled && <Badge tone="slate">No 2FA</Badge>}
                      {m.recoveryEnrolled && <Badge tone="brand">Recovery</Badge>}
                      {m.ssoLinked && <Badge tone="brand">SSO</Badge>}
                      {m.scimManaged && <Badge tone="slate">SCIM</Badge>}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-500">
                    {m.role !== 'member'
                      ? 'All collections'
                      : [
                          m.groups.map(groupName).filter(Boolean).join(', '),
                          m.collections.length ? `${m.collections.length} collection${m.collections.length === 1 ? '' : 's'}` : '',
                        ]
                          .filter(Boolean)
                          .join(' · ') || 'No access'}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex justify-end gap-0.5">
                      {m.status === 'accepted' && !m.revoked && canManage(m) && (
                        <button className="btn-secondary px-2.5 py-1 text-xs" onClick={() => setDialog({ kind: 'confirm', members: [m] })}>Confirm</button>
                      )}
                      {m.status === 'invited' && (
                        <button className="icon-btn" title="Resend invitation" onClick={() => act(() => reinviteMember(orgId, m.id), 'Invitation re-sent')}>
                          <Mail className="h-4 w-4" />
                        </button>
                      )}
                      {canManage(m) && recoveryOn && m.recoveryEnrolled && m.status === 'confirmed' && !m.revoked && (
                        <button className="icon-btn" title="Reset master password (account recovery)" onClick={() => setDialog({ kind: 'recover', member: m })}>
                          <LifeBuoy className="h-4 w-4" />
                        </button>
                      )}
                      {canManage(m) && (
                        <>
                          <button className="icon-btn" title="Edit role and access" onClick={() => setDialog({ kind: 'edit', member: m })}>
                            <Pencil className="h-4 w-4" />
                          </button>
                          <button
                            className="icon-btn"
                            title={m.revoked ? 'Restore access' : 'Revoke access'}
                            onClick={() => act(() => setMemberRevoked(orgId, m.id, !m.revoked), m.revoked ? 'Access restored' : 'Access revoked')}
                          >
                            {m.revoked ? <RotateCcw className="h-4 w-4" /> : <Ban className="h-4 w-4" />}
                          </button>
                          <button className="icon-btn hover:text-red-600" title="Remove from organization" onClick={() => setDialog({ kind: 'remove', member: m })}>
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {dialog?.kind === 'invite' && <InviteDialog onClose={() => setDialog(null)} />}
      {dialog?.kind === 'edit' && <EditMemberDialog member={dialog.member} onClose={() => setDialog(null)} />}
      {dialog?.kind === 'confirm' && <ConfirmDialog members={dialog.members} onClose={() => setDialog(null)} />}
      {dialog?.kind === 'remove' && <RemoveDialog member={dialog.member} onClose={() => setDialog(null)} />}
      {dialog?.kind === 'recover' && <RecoverDialog member={dialog.member} onClose={() => setDialog(null)} />}
    </div>
  );
}
