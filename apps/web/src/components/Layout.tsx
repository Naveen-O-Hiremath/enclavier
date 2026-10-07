import { useState, type ReactNode } from 'react';
import { NavLink, useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import {
  Archive,
  Building2,
  CreditCard,
  Plus,
  Shield,
  FileText,
  Folder,
  HeartPulse,
  FolderPlus,
  KeyRound,
  Layers,
  Lock,
  Menu,
  Settings,
  Star,
  Trash2,
  UserSquare,
  Wand2,
} from 'lucide-react';
import { useSession } from '../lib/session';
import { FolderDialog } from '../pages/FolderDialog';
import { CreateOrgDialog } from '../pages/CreateOrgDialog';
import { AccountBanners, ForcePasswordChange } from '../pages/AccountGuards';
import { Logo } from './ui';

function NavItem(props: { to: string; icon: ReactNode; label: string; count?: number; active: boolean; onNavigate?: () => void }) {
  return (
    <NavLink
      to={props.to}
      onClick={props.onNavigate}
      className={`flex items-center gap-2.5 rounded-lg px-2.5 py-1.5 text-sm transition ${
        props.active
          ? 'bg-brand-50 font-medium text-brand-700 dark:bg-brand-500/10 dark:text-brand-400'
          : 'text-slate-600 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800/60'
      }`}
    >
      <span className="[&>svg]:h-4 [&>svg]:w-4">{props.icon}</span>
      <span className="flex-1 truncate">{props.label}</span>
      {props.count !== undefined && <span className="text-xs text-slate-400">{props.count}</span>}
    </NavLink>
  );
}

export function Layout({ children }: { children: ReactNode }) {
  const { items, folders, profile, lock, organizations, collections } = useSession();
  const [params] = useSearchParams();
  const location = useLocation();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [newFolder, setNewFolder] = useState(false);
  const [newOrg, setNewOrg] = useState(false);

  const view = location.pathname === '/vault' ? (params.get('view') ?? 'all') : null;
  const live = items.filter((i) => !i.deletedAt);
  const count = (pred: (i: (typeof items)[number]) => boolean) => live.filter(pred).length;
  const close = () => setOpen(false);

  const sidebar = (
    <aside className="flex h-full w-64 shrink-0 flex-col border-r border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
      <div className="px-4 py-4">
        <Logo />
      </div>
      <nav className="flex-1 space-y-5 overflow-y-auto px-3 pb-4">
        <div className="space-y-0.5">
          <NavItem to="/vault" icon={<Layers />} label="All items" count={live.length} active={view === 'all'} onNavigate={close} />
          <NavItem to="/vault?view=favorites" icon={<Star />} label="Favorites" count={count((i) => !!i.data.favorite)} active={view === 'favorites'} onNavigate={close} />
        </div>
        <div>
          <div className="mb-1 px-2.5 text-[11px] font-semibold tracking-wider text-slate-400 uppercase">Types</div>
          <div className="space-y-0.5">
            <NavItem to="/vault?view=type:login" icon={<KeyRound />} label="Logins" count={count((i) => i.data.type === 'login')} active={view === 'type:login'} onNavigate={close} />
            <NavItem to="/vault?view=type:card" icon={<CreditCard />} label="Cards" count={count((i) => i.data.type === 'card')} active={view === 'type:card'} onNavigate={close} />
            <NavItem to="/vault?view=type:identity" icon={<UserSquare />} label="Identities" count={count((i) => i.data.type === 'identity')} active={view === 'type:identity'} onNavigate={close} />
            <NavItem to="/vault?view=type:note" icon={<FileText />} label="Secure notes" count={count((i) => i.data.type === 'note')} active={view === 'type:note'} onNavigate={close} />
          </div>
        </div>
        <div>
          <div className="mb-1 flex items-center justify-between px-2.5">
            <span className="text-[11px] font-semibold tracking-wider text-slate-400 uppercase">Folders</span>
            <button className="icon-btn h-6 w-6" onClick={() => setNewFolder(true)} aria-label="New folder">
              <FolderPlus className="h-3.5 w-3.5" />
            </button>
          </div>
          <div className="space-y-0.5">
            {[...folders]
              .sort((a, b) => a.name.localeCompare(b.name))
              .map((f) => (
                <NavItem
                  key={f.id}
                  to={`/vault?view=folder:${f.id}`}
                  icon={<Folder />}
                  label={f.name}
                  count={count((i) => i.folderId === f.id)}
                  active={view === `folder:${f.id}`}
                  onNavigate={close}
                />
              ))}
            {folders.length === 0 && <div className="px-2.5 py-1 text-xs text-slate-400">No folders yet</div>}
          </div>
        </div>
        <div>
          <div className="mb-1 flex items-center justify-between px-2.5">
            <span className="text-[11px] font-semibold tracking-wider text-slate-400 uppercase">Organizations</span>
            <button className="icon-btn h-6 w-6" onClick={() => setNewOrg(true)} aria-label="New organization">
              <Plus className="h-3.5 w-3.5" />
            </button>
          </div>
          <div className="space-y-3">
            {organizations.map((org) => {
              const cols = collections.filter((c) => c.orgId === org.id).sort((a, b) => a.name.localeCompare(b.name));
              const admin = org.role !== 'member' && org.status === 'confirmed';
              return (
                <div key={org.id}>
                  <div className="flex items-center gap-2 px-2.5 py-1 text-sm font-medium text-slate-700 dark:text-slate-300">
                    <Building2 className="h-4 w-4 text-slate-400" />
                    <span className="flex-1 truncate">{org.name}</span>
                  </div>
                  {org.status !== 'confirmed' ? (
                    <div className="px-2.5 pl-9 text-xs text-amber-600 dark:text-amber-400">Waiting for an admin to confirm you</div>
                  ) : (
                    <div className="space-y-0.5 pl-3">
                      {cols.map((c) => (
                        <NavItem
                          key={c.id}
                          to={`/vault?view=collection:${c.id}`}
                          icon={<Archive />}
                          label={c.name}
                          count={count((i) => i.collectionId === c.id)}
                          active={view === `collection:${c.id}`}
                          onNavigate={close}
                        />
                      ))}
                      {cols.length === 0 && <div className="px-2.5 py-1 text-xs text-slate-400">No collections assigned</div>}
                      {admin && (
                        <NavItem
                          to={`/orgs/${org.id}`}
                          icon={<Shield />}
                          label="Admin console"
                          active={location.pathname.startsWith(`/orgs/${org.id}`)}
                          onNavigate={close}
                        />
                      )}
                    </div>
                  )}
                </div>
              );
            })}
            {organizations.length === 0 && (
              <button className="w-full px-2.5 py-1 text-left text-xs text-slate-400 hover:text-brand-600" onClick={() => setNewOrg(true)}>
                Create an organization to share with your team
              </button>
            )}
          </div>
        </div>
        <div className="space-y-0.5">
          <NavItem to="/vault?view=trash" icon={<Trash2 />} label="Trash" count={items.length - live.length} active={view === 'trash'} onNavigate={close} />
          <NavItem to="/health" icon={<HeartPulse />} label="Vault health" active={location.pathname === '/health'} onNavigate={close} />
          <NavItem to="/generator" icon={<Wand2 />} label="Generator" active={location.pathname === '/generator'} onNavigate={close} />
          <NavItem to="/settings" icon={<Settings />} label="Settings" active={location.pathname === '/settings'} onNavigate={close} />
        </div>
      </nav>
      <div className="flex items-center gap-3 border-t border-slate-200 p-3 dark:border-slate-800">
        <div className="flex h-8 w-8 items-center justify-center rounded-full bg-brand-100 text-sm font-semibold text-brand-700 dark:bg-brand-500/20 dark:text-brand-400">
          {profile?.name.charAt(0).toUpperCase()}
        </div>
        <div className="min-w-0 flex-1">
          <div className="truncate text-sm font-medium">{profile?.name}</div>
          <div className="truncate text-xs text-slate-500">{profile?.email}</div>
        </div>
        <button className="icon-btn" onClick={lock} title="Lock vault" aria-label="Lock vault">
          <Lock className="h-4 w-4" />
        </button>
      </div>
    </aside>
  );

  return (
    <div className="flex h-full">
      <div className="hidden md:flex">{sidebar}</div>
      {open && (
        <div className="fixed inset-0 z-30 flex md:hidden" onClick={(e) => e.target === e.currentTarget && close()}>
          {sidebar}
          <div className="flex-1 bg-slate-950/40" onClick={close} />
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex items-center gap-2 border-b border-slate-200 bg-white px-3 py-2 md:hidden dark:border-slate-800 dark:bg-slate-900">
          <button className="icon-btn" onClick={() => setOpen(true)} aria-label="Menu">
            <Menu className="h-5 w-5" />
          </button>
          <Logo />
        </div>
        <AccountBanners />
        <main className="min-h-0 flex-1">{children}</main>
        <ForcePasswordChange />
      </div>
      {newOrg && <CreateOrgDialog onClose={() => setNewOrg(false)} onCreated={(id) => navigate(`/orgs/${id}`)} />}
      {newFolder && (
        <FolderDialog
          onClose={() => setNewFolder(false)}
          onSaved={(id) => navigate(`/vault?view=folder:${id}`)}
        />
      )}
    </div>
  );
}
