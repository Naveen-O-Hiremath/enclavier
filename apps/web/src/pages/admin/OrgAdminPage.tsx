import { NavLink, Navigate, Route, Routes, useParams } from 'react-router-dom';
import { Archive, BadgeCheck, Building2, Fingerprint, HeartPulse, Radio, ScrollText, Settings2, ShieldCheck, Users, UsersRound } from 'lucide-react';
import { useSession } from '../../lib/session';
import { EmptyState } from '../../components/ui';
import { OrgDataProvider, useOrgData } from './shared';
import { MembersTab } from './MembersTab';
import { GroupsTab } from './GroupsTab';
import { CollectionsTab } from './CollectionsTab';
import { EventsTab } from './EventsTab';
import { OrgSettingsTab } from './OrgSettingsTab';
import { PoliciesTab } from './PoliciesTab';
import { StreamingTab } from './StreamingTab';
import { ComplianceTab } from './ComplianceTab';
import { OrgHealthTab } from './OrgHealthTab';
import { SsoTab } from './SsoTab';

const TABS = [
  { path: 'members', label: 'Members', icon: Users },
  { path: 'groups', label: 'Groups', icon: UsersRound },
  { path: 'collections', label: 'Collections', icon: Archive },
  { path: 'policies', label: 'Policies', icon: ShieldCheck },
  { path: 'sso', label: 'Single sign-on', icon: Fingerprint },
  { path: 'events', label: 'Audit log', icon: ScrollText },
  { path: 'streaming', label: 'Log streaming', icon: Radio },
  { path: 'health', label: 'Health', icon: HeartPulse },
  { path: 'compliance', label: 'Compliance', icon: BadgeCheck },
  { path: 'settings', label: 'Settings', icon: Settings2 },
];

function Header({ name, role }: { name: string; role: string }) {
  const { members, loading } = useOrgData();
  const pending = members.filter((m) => m.status === 'accepted' && !m.revoked).length;
  return (
    <div className="border-b border-slate-200 bg-white px-6 pt-5 dark:border-slate-800 dark:bg-slate-900">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand-50 text-brand-600 dark:bg-brand-500/10">
          <Building2 className="h-5 w-5" />
        </div>
        <div>
          <h1 className="text-lg font-semibold">{name}</h1>
          <p className="text-xs text-slate-500">
            Admin console · you are {role === 'owner' ? 'an owner' : 'an admin'}
            {!loading && ` · ${members.length} member${members.length === 1 ? '' : 's'}`}
          </p>
        </div>
      </div>
      <nav className="-mb-px mt-4 flex gap-1 overflow-x-auto">
        {TABS.map((t) => (
          <NavLink
            key={t.path}
            to={t.path}
            className={({ isActive }) =>
              `flex items-center gap-2 border-b-2 px-3 py-2 text-sm whitespace-nowrap transition ${
                isActive
                  ? 'border-brand-600 font-medium text-brand-700 dark:text-brand-400'
                  : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
              }`
            }
          >
            <t.icon className="h-4 w-4" />
            {t.label}
            {t.path === 'members' && pending > 0 && (
              <span className="rounded-full bg-amber-500 px-1.5 text-[10px] font-semibold text-white">{pending}</span>
            )}
          </NavLink>
        ))}
      </nav>
    </div>
  );
}

export function OrgAdminPage() {
  const { orgId } = useParams();
  const org = useSession((s) => s.organizations.find((o) => o.id === orgId));

  if (!org || org.status !== 'confirmed' || org.role === 'member') {
    return <EmptyState icon={<Building2 className="h-5 w-5" />} title="Admin access required" hint="Only owners and admins of this organization can open its console." />;
  }

  return (
    <OrgDataProvider orgId={org.id}>
      <div className="flex h-full flex-col">
        <Header name={org.name} role={org.role} />
        <div className="min-h-0 flex-1 overflow-y-auto">
          <div className="mx-auto max-w-5xl p-6">
            <Routes>
              <Route path="members" element={<MembersTab />} />
              <Route path="groups" element={<GroupsTab />} />
              <Route path="collections" element={<CollectionsTab />} />
              <Route path="policies" element={<PoliciesTab />} />
              <Route path="sso" element={<SsoTab />} />
              <Route path="events" element={<EventsTab />} />
              <Route path="streaming" element={<StreamingTab />} />
              <Route path="health" element={<OrgHealthTab />} />
              <Route path="compliance" element={<ComplianceTab />} />
              <Route path="settings" element={<OrgSettingsTab />} />
              <Route path="*" element={<Navigate to="members" replace />} />
            </Routes>
          </div>
        </div>
      </div>
    </OrgDataProvider>
  );
}
