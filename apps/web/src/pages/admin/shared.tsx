import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { Search } from 'lucide-react';
import type { OrgGroup, OrgMember, OrgRole, Permission } from '@enclavier/shared';
import { listCollections, listGroups, listMembers, PERMISSION_LABELS, ROLE_LABELS, type AdminCollection } from '../../lib/orgs';
import { errorMessage, toast } from '../../components/Toast';

// ---- data -------------------------------------------------------------------

export interface OrgData {
  orgId: string;
  members: OrgMember[];
  groups: OrgGroup[];
  collections: AdminCollection[];
  loading: boolean;
  reload: () => Promise<void>;
}

const Ctx = createContext<OrgData | null>(null);

export function OrgDataProvider({ orgId, children }: { orgId: string; children: ReactNode }) {
  const [state, setState] = useState<Omit<OrgData, 'reload' | 'orgId'>>({ members: [], groups: [], collections: [], loading: true });
  const reload = useCallback(async () => {
    try {
      const [members, groups, collections] = await Promise.all([listMembers(orgId), listGroups(orgId), listCollections(orgId)]);
      setState({ members, groups, collections, loading: false });
    } catch (e) {
      toast(errorMessage(e), 'error');
      setState((s) => ({ ...s, loading: false }));
    }
  }, [orgId]);
  useEffect(() => {
    setState({ members: [], groups: [], collections: [], loading: true });
    void reload();
  }, [reload]);
  return <Ctx.Provider value={{ ...state, orgId, reload }}>{children}</Ctx.Provider>;
}

export function useOrgData(): OrgData {
  const v = useContext(Ctx);
  if (!v) throw new Error('useOrgData outside provider');
  return v;
}

// ---- pickers ----------------------------------------------------------------

export type GrantMap = Record<string, Permission | undefined>;

export function toGrantMap<T>(list: T[], id: (t: T) => string, perm: (t: T) => Permission): GrantMap {
  return Object.fromEntries(list.map((t) => [id(t), perm(t)]));
}

export function fromGrantMap(map: GrantMap): { id: string; permission: Permission }[] {
  return Object.entries(map).flatMap(([id, permission]) => (permission ? [{ id, permission }] : []));
}

export interface PickerOption {
  id: string;
  label: string;
  sublabel?: string;
}

function FilterBox({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <div className="relative">
      <Search className="absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
      <input className="input py-1.5 pl-8 text-xs" placeholder={placeholder} value={value} onChange={(e) => onChange(e.target.value)} />
    </div>
  );
}

const matches = (o: PickerOption, q: string) => `${o.label} ${o.sublabel ?? ''}`.toLowerCase().includes(q.trim().toLowerCase());

/** Checklist with a permission level per selected row. */
export function GrantEditor(props: { options: PickerOption[]; value: GrantMap; onChange: (v: GrantMap) => void; empty: string; defaultPermission?: Permission }) {
  const [q, setQ] = useState('');
  const visible = props.options.filter((o) => matches(o, q));
  if (props.options.length === 0) return <p className="text-sm text-slate-500">{props.empty}</p>;
  return (
    <div className="space-y-2">
      {props.options.length > 6 && <FilterBox value={q} onChange={setQ} placeholder="Filter" />}
      <div className="max-h-64 divide-y divide-slate-100 overflow-y-auto rounded-lg border border-slate-200 dark:divide-slate-800 dark:border-slate-800">
        {visible.map((o) => {
          const perm = props.value[o.id];
          return (
            <div key={o.id} className="flex items-center gap-3 px-3 py-2">
              <input
                type="checkbox"
                checked={!!perm}
                onChange={(e) => props.onChange({ ...props.value, [o.id]: e.target.checked ? (props.defaultPermission ?? 'view') : undefined })}
                aria-label={o.label}
              />
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm">{o.label}</div>
                {o.sublabel && <div className="truncate text-xs text-slate-500">{o.sublabel}</div>}
              </div>
              <select
                className="input w-36 py-1 text-xs"
                disabled={!perm}
                value={perm ?? ''}
                onChange={(e) => props.onChange({ ...props.value, [o.id]: e.target.value as Permission })}
              >
                {!perm && <option value="">No access</option>}
                {(Object.keys(PERMISSION_LABELS) as Permission[]).map((p) => (
                  <option key={p} value={p} title={PERMISSION_LABELS[p].hint}>
                    {PERMISSION_LABELS[p].label}
                  </option>
                ))}
              </select>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/** Plain multi-select checklist. */
export function CheckList(props: { options: PickerOption[]; value: string[]; onChange: (v: string[]) => void; empty: string }) {
  const [q, setQ] = useState('');
  const selected = new Set(props.value);
  const visible = props.options.filter((o) => matches(o, q));
  if (props.options.length === 0) return <p className="text-sm text-slate-500">{props.empty}</p>;
  return (
    <div className="space-y-2">
      {props.options.length > 6 && <FilterBox value={q} onChange={setQ} placeholder="Filter" />}
      <div className="max-h-56 divide-y divide-slate-100 overflow-y-auto rounded-lg border border-slate-200 dark:divide-slate-800 dark:border-slate-800">
        {visible.map((o) => (
          <label key={o.id} className="flex cursor-pointer items-center gap-3 px-3 py-2 hover:bg-slate-50 dark:hover:bg-slate-800/50">
            <input
              type="checkbox"
              checked={selected.has(o.id)}
              onChange={(e) => props.onChange(e.target.checked ? [...props.value, o.id] : props.value.filter((x) => x !== o.id))}
            />
            <div className="min-w-0">
              <div className="truncate text-sm">{o.label}</div>
              {o.sublabel && <div className="truncate text-xs text-slate-500">{o.sublabel}</div>}
            </div>
          </label>
        ))}
      </div>
    </div>
  );
}

export function RolePicker({ value, onChange, allowOwner }: { value: OrgRole; onChange: (r: OrgRole) => void; allowOwner: boolean }) {
  return (
    <div className="grid gap-2 sm:grid-cols-3">
      {(Object.keys(ROLE_LABELS) as OrgRole[]).map((r) => {
        const disabled = r === 'owner' && !allowOwner;
        return (
          <button
            type="button"
            key={r}
            disabled={disabled}
            onClick={() => onChange(r)}
            className={`rounded-lg border p-3 text-left transition disabled:cursor-not-allowed disabled:opacity-40 ${
              value === r
                ? 'border-brand-500 bg-brand-50 ring-2 ring-brand-500/20 dark:bg-brand-500/10'
                : 'border-slate-200 hover:border-slate-300 dark:border-slate-700'
            }`}
          >
            <div className="text-sm font-medium">{ROLE_LABELS[r].label}</div>
            <div className="mt-0.5 text-xs text-slate-500">{ROLE_LABELS[r].hint}</div>
          </button>
        );
      })}
    </div>
  );
}

export function Badge({ tone, children }: { tone: 'green' | 'amber' | 'slate' | 'red' | 'brand'; children: ReactNode }) {
  const tones = {
    green: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-400',
    amber: 'bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-400',
    slate: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300',
    red: 'bg-red-100 text-red-700 dark:bg-red-500/15 dark:text-red-400',
    brand: 'bg-brand-100 text-brand-700 dark:bg-brand-500/15 dark:text-brand-400',
  };
  return <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium ${tones[tone]}`}>{children}</span>;
}

export const memberLabel = (m: OrgMember) => m.name ?? m.email;
