import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Download, Search, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { AuditVerifyResult, OrgEvent } from '@enclavier/shared';
import { api, apiText } from '../../lib/api';
import { Spinner } from '../../components/ui';
import { errorMessage, toast } from '../../components/Toast';
import { useOrgData } from './shared';

export const EVENT_LABELS: Record<string, string> = {
  'org.created': 'Created the organization',
  'org.updated': 'Renamed the organization',
  'org.policy_updated': 'Changed a policy',
  'org.recovery_kit_created': 'Created a break-glass recovery kit',
  'org.recovery_kit_deleted': 'Deleted the break-glass recovery kit',
  'org.break_glass_recovered': 'Used break-glass recovery',
  'org.audit_exported': 'Exported the audit log',
  'org.compliance_report_generated': 'Generated a compliance report',
  'org.log_destination_created': 'Added a log destination',
  'org.log_destination_updated': 'Changed a log destination',
  'org.log_destination_deleted': 'Removed a log destination',
  'org.sso_updated': 'Changed single sign-on',
  'org.domain_added': 'Added a domain',
  'org.domain_verified': 'Verified a domain',
  'org.domain_removed': 'Removed a domain',
  'org.scim_token_created': 'Created a SCIM token',
  'org.scim_token_revoked': 'Revoked a SCIM token',
  'user.sso_login_failed': 'SSO sign-in rejected',
  'user.sso_linked': 'Linked an account to SSO',
  'user.sso_provisioned': 'Account created by SSO (JIT)',
  'scim.user_provisioned': 'SCIM: user provisioned',
  'scim.user_updated': 'SCIM: user updated',
  'scim.user_deprovisioned': 'SCIM: user deactivated',
  'scim.user_deleted': 'SCIM: user removed',
  'scim.group_created': 'SCIM: group created',
  'scim.group_updated': 'SCIM: group updated',
  'scim.group_deleted': 'SCIM: group deleted',
  'group.synced': 'Group membership synced from SSO',
  'device.approval_requested': 'Asked admins to approve a device',
  'device.approved': 'Approved a device',
  'device.denied': 'Denied a device',
  'member.invited': 'Invited a member',
  'member.reinvited': 'Re-sent an invitation',
  'member.accepted': 'Accepted an invitation',
  'member.confirmed': 'Confirmed a member',
  'member.updated': 'Changed a member’s role or access',
  'member.revoked': 'Revoked a member',
  'member.restored': 'Restored a member',
  'member.removed': 'Removed a member',
  'member.left': 'Left the organization',
  'member.recovery_enrolled': 'Enrolled in account recovery',
  'member.recovery_withdrawn': 'Withdrew from account recovery',
  'member.account_recovered': 'Reset a member’s master password',
  'group.created': 'Created a group',
  'group.updated': 'Updated a group',
  'group.deleted': 'Deleted a group',
  'collection.created': 'Created a collection',
  'collection.updated': 'Changed collection access',
  'collection.deleted': 'Deleted a collection',
  'item.created': 'Created an item',
  'item.updated': 'Updated an item',
  'item.shared': 'Moved a personal item into a collection',
  'item.trashed': 'Moved an item to trash',
  'item.restored': 'Restored an item',
  'item.deleted': 'Permanently deleted an item',
};

const CATEGORIES = [
  { value: '', label: 'All events' },
  { value: 'member.', label: 'Members' },
  { value: 'item.', label: 'Items' },
  { value: 'collection.', label: 'Collections' },
  { value: 'group.', label: 'Groups' },
  { value: 'org.', label: 'Organization & policies' },
];

const SENSITIVE = /revoked|removed|deleted|confirmed|recovered|break_glass|policy|exported|account_recovered/;

export function EventsTab() {
  const { orgId, members, groups, collections } = useOrgData();
  const [events, setEvents] = useState<OrgEvent[] | null>(null);
  const [more, setMore] = useState(false);
  const [filters, setFilters] = useState({ action: '', actor: '', from: '', to: '' });
  const [verify, setVerify] = useState<AuditVerifyResult | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const qs = useCallback(
    (extra: Record<string, string | number | undefined> = {}) => {
      const p = new URLSearchParams();
      if (filters.action) p.set('action', filters.action);
      if (filters.actor) p.set('actor', filters.actor);
      if (filters.from) p.set('from', new Date(filters.from).toISOString());
      if (filters.to) p.set('to', new Date(`${filters.to}T23:59:59`).toISOString());
      for (const [k, v] of Object.entries(extra)) if (v !== undefined) p.set(k, String(v));
      return p.toString();
    },
    [filters],
  );

  const load = useCallback(async () => {
    try {
      const rows = await api<OrgEvent[]>('GET', `/api/orgs/${orgId}/events?${qs({ limit: 100 })}`);
      setEvents(rows);
      setMore(rows.length === 100);
    } catch (e) {
      toast(errorMessage(e), 'error');
    }
  }, [orgId, qs]);

  useEffect(() => void load(), [orgId]); // eslint-disable-line react-hooks/exhaustive-deps

  async function loadMore() {
    if (!events?.length) return;
    const next = await api<OrgEvent[]>('GET', `/api/orgs/${orgId}/events?${qs({ limit: 100, before: events.at(-1)!.id })}`);
    setEvents([...events, ...next]);
    setMore(next.length === 100);
  }

  async function runVerify() {
    setBusy('verify');
    try {
      setVerify(await api<AuditVerifyResult>('GET', `/api/orgs/${orgId}/audit/verify`));
    } catch (e) {
      toast(errorMessage(e), 'error');
    } finally {
      setBusy(null);
    }
  }

  async function download(format: 'csv' | 'ndjson') {
    setBusy(format);
    try {
      const text = await apiText(`/api/orgs/${orgId}/audit/export?${qs({ format })}`);
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([text], { type: format === 'csv' ? 'text/csv' : 'application/x-ndjson' }));
      a.download = `enclavier-audit-${new Date().toISOString().slice(0, 10)}.${format}`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    } catch (e) {
      toast(errorMessage(e), 'error');
    } finally {
      setBusy(null);
    }
  }

  function target(e: OrgEvent): string {
    const meta = e.metadata as { email?: string; name?: string };
    if (meta.email) return meta.email;
    if (e.targetType === 'member') return members.find((m) => m.id === e.targetId)?.email ?? '';
    if (e.targetType === 'group') return groups.find((g) => g.id === e.targetId)?.name ?? meta.name ?? '';
    if (e.targetType === 'collection') return collections.find((c) => c.id === e.targetId)?.name ?? '';
    if (e.targetType === 'policy') return e.targetId ?? '';
    if (e.targetType === 'org') return meta.name ?? '';
    return e.targetId ? `${e.targetType} ${e.targetId.slice(0, 8)}` : '';
  }

  const submit = (ev: FormEvent) => {
    ev.preventDefault();
    void load();
  };

  return (
    <div className="space-y-4">
      <section className={`card flex flex-wrap items-center gap-3 p-4 ${verify && !verify.ok ? 'border-red-300 dark:border-red-900' : ''}`}>
        {verify?.ok === false ? <ShieldAlert className="h-5 w-5 text-red-600" /> : <ShieldCheck className={`h-5 w-5 ${verify ? 'text-emerald-600' : 'text-slate-400'}`} />}
        <div className="min-w-0 flex-1 text-sm">
          {!verify && <span className="text-slate-600 dark:text-slate-300">Every event is linked into this organization's SHA-256 hash chain. Verify that no event was altered or deleted.</span>}
          {verify?.ok && (
            <span>
              <strong>Intact.</strong> {verify.checked} events verified
              {verify.head && <> · head #{verify.head.seq} <code className="font-mono text-xs">{verify.head.hash.slice(0, 16)}…</code></>}
              {verify.legacy > 0 && ` · ${verify.legacy} earlier events covered by the global chain`}
            </span>
          )}
          {verify?.ok === false && (
            <span className="text-red-700 dark:text-red-400">
              <strong>Integrity failure at event #{verify.brokenAtSeq}:</strong> {verify.reason}. The log was changed outside Enclavier.
            </span>
          )}
        </div>
        <button className="btn-secondary" onClick={runVerify} disabled={busy === 'verify'}>{busy === 'verify' && <Spinner />} Verify integrity</button>
      </section>

      <form onSubmit={submit} className="flex flex-wrap items-end gap-2">
        <div>
          <label className="label">Category</label>
          <select className="input py-1.5" value={filters.action} onChange={(e) => setFilters({ ...filters, action: e.target.value })}>
            {CATEGORIES.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
          </select>
        </div>
        <div>
          <label className="label">Actor</label>
          <input className="input py-1.5" placeholder="e-mail contains…" value={filters.actor} onChange={(e) => setFilters({ ...filters, actor: e.target.value })} />
        </div>
        <div>
          <label className="label">From</label>
          <input className="input py-1.5" type="date" value={filters.from} onChange={(e) => setFilters({ ...filters, from: e.target.value })} />
        </div>
        <div>
          <label className="label">To</label>
          <input className="input py-1.5" type="date" value={filters.to} onChange={(e) => setFilters({ ...filters, to: e.target.value })} />
        </div>
        <button className="btn-primary"><Search className="h-4 w-4" /> Apply</button>
        <div className="flex-1" />
        <button type="button" className="btn-secondary" onClick={() => download('csv')} disabled={!!busy}>{busy === 'csv' ? <Spinner /> : <Download className="h-4 w-4" />} CSV</button>
        <button type="button" className="btn-secondary" onClick={() => download('ndjson')} disabled={!!busy}>{busy === 'ndjson' ? <Spinner /> : <Download className="h-4 w-4" />} JSON</button>
      </form>

      {!events ? (
        <Spinner className="h-6 w-6" />
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[720px] text-sm">
            <thead className="border-b border-slate-200 text-left text-xs text-slate-500 uppercase dark:border-slate-800">
              <tr>
                <th className="px-4 py-2.5 font-medium">#</th>
                <th className="px-4 py-2.5 font-medium">When</th>
                <th className="px-4 py-2.5 font-medium">Who</th>
                <th className="px-4 py-2.5 font-medium">Action</th>
                <th className="px-4 py-2.5 font-medium">Target</th>
                <th className="px-4 py-2.5 font-medium">IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {events.map((e) => (
                <tr key={e.id} title={e.userAgent ?? undefined}>
                  <td className="px-4 py-2.5 font-mono text-xs text-slate-400">{e.orgSeq ?? '–'}</td>
                  <td className="px-4 py-2.5 text-xs whitespace-nowrap text-slate-500">{new Date(e.createdAt).toLocaleString()}</td>
                  <td className="px-4 py-2.5">{e.actorEmail ?? 'deleted user'}</td>
                  <td className={`px-4 py-2.5 ${SENSITIVE.test(e.action) ? 'font-medium' : ''}`}>{EVENT_LABELS[e.action] ?? e.action}</td>
                  <td className="max-w-48 truncate px-4 py-2.5 text-slate-500">{target(e)}</td>
                  <td className="px-4 py-2.5 font-mono text-xs text-slate-500">{e.ip}</td>
                </tr>
              ))}
              {events.length === 0 && (
                <tr><td colSpan={6} className="px-4 py-8 text-center text-slate-500">No events match these filters.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
      {more && <button className="btn-secondary" onClick={loadMore}>Load older events</button>}
    </div>
  );
}
