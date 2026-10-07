import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { AlertOctagon, Clock, HeartPulse, LockOpen, MailWarning, Repeat, ShieldCheck, ShieldX } from 'lucide-react';
import type { BreachedAccount } from '@enclavier/shared';
import { analyzeVault, breachStatus, myBreachedAccounts, type HealthReport, type IssueKind } from '../lib/health';
import { useSession, type VaultItem } from '../lib/session';
import { EmptyState, Spinner } from '../components/ui';
import { errorMessage, toast } from '../components/Toast';

const KINDS: Record<IssueKind, { label: string; icon: typeof ShieldX; tone: string; hint: string }> = {
  exposed: { label: 'Exposed in breaches', icon: ShieldX, tone: 'text-red-600 bg-red-50 dark:bg-red-500/10', hint: 'Change these first: attackers try breached passwords everywhere.' },
  reused: { label: 'Reused', icon: Repeat, tone: 'text-orange-600 bg-orange-50 dark:bg-orange-500/10', hint: 'One breach unlocks every account sharing the password.' },
  weak: { label: 'Weak', icon: AlertOctagon, tone: 'text-amber-600 bg-amber-50 dark:bg-amber-500/10', hint: 'Guessable from dictionaries and common patterns.' },
  old: { label: 'Older than a year', icon: Clock, tone: 'text-slate-600 bg-slate-100 dark:bg-slate-800', hint: 'Consider rotating long-lived credentials.' },
  insecure: { label: 'Insecure website', icon: LockOpen, tone: 'text-slate-600 bg-slate-100 dark:bg-slate-800', hint: 'The saved address uses http://, not https://.' },
};

function Tile({ label, value, icon, tone }: { label: string; value: ReactNode; icon: ReactNode; tone: string }) {
  return (
    <div className="card flex items-center gap-3 p-4">
      <div className={`flex h-9 w-9 items-center justify-center rounded-lg ${tone}`}>{icon}</div>
      <div>
        <div className="text-xl font-semibold">{value}</div>
        <div className="text-xs text-slate-500">{label}</div>
      </div>
    </div>
  );
}

/** Health analysis over a set of vault items. Used for the personal vault and, by admins, for an organization. */
export function HealthView({ items, scopeLabel, showAccountBreaches }: { items: VaultItem[]; scopeLabel: string; showAccountBreaches?: boolean }) {
  const [report, setReport] = useState<HealthReport | null>(null);
  const [progress, setProgress] = useState<[number, number]>([0, 0]);
  const [running, setRunning] = useState(false);
  const [filter, setFilter] = useState<IssueKind | null>(null);
  const [breaches, setBreaches] = useState<{ status: { passwords: boolean; accounts: boolean }; accounts?: BreachedAccount[] } | null>(null);

  useEffect(() => {
    breachStatus().then((status) => setBreaches({ status }), () => setBreaches({ status: { passwords: false, accounts: false } }));
  }, []);

  async function run() {
    setRunning(true);
    try {
      setReport(await analyzeVault(items, { checkBreaches: !!breaches?.status.passwords, onProgress: (d, t) => setProgress([d, t]) }));
    } catch (e) {
      toast(errorMessage(e), 'error');
    } finally {
      setRunning(false);
    }
  }

  const visible = useMemo(() => (report ? report.items.filter((i) => !filter || i.issues.some((x) => x.kind === filter)) : []), [report, filter]);
  const scorePct = report && report.total ? Math.round((report.healthy / report.total) * 100) : 100;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <p className="flex-1 text-sm text-slate-500">
          Analyses {scopeLabel} on this device. Passwords never leave your browser; breach checks send only the first 5 characters of a SHA-1 hash
          (k-anonymity).
          {breaches && !breaches.status.passwords && ' Breach checks are disabled on this server.'}
        </p>
        <button className="btn-primary" onClick={run} disabled={running || !breaches}>
          {running ? <Spinner /> : <HeartPulse className="h-4 w-4" />}
          {running ? `Checking ${progress[0]}/${progress[1]}…` : report ? 'Re-run check' : 'Run health check'}
        </button>
      </div>

      {report && (
        <>
          <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-6">
            <Tile label="Healthy" value={`${scorePct}%`} icon={<ShieldCheck className="h-4 w-4" />} tone="text-emerald-600 bg-emerald-50 dark:bg-emerald-500/10" />
            {(Object.keys(KINDS) as IssueKind[]).map((k) => {
              const K = KINDS[k];
              return (
                <button key={k} className="text-left" onClick={() => setFilter(filter === k ? null : k)}>
                  <div className={filter === k ? 'rounded-xl ring-2 ring-brand-500' : ''}>
                    <Tile label={K.label} value={report.counts[k]} icon={<K.icon className="h-4 w-4" />} tone={K.tone} />
                  </div>
                </button>
              );
            })}
          </div>
          {report.breachCheck === 'failed' && <p className="text-xs text-amber-600">The breach database could not be reached; exposure results are incomplete.</p>}
          {filter && <p className="text-xs text-slate-500">{KINDS[filter].hint}</p>}

          {report.total === 0 ? (
            <div className="card"><EmptyState icon={<ShieldCheck className="h-5 w-5" />} title="No logins with passwords to check" /></div>
          ) : visible.length === 0 ? (
            <div className="card"><EmptyState icon={<ShieldCheck className="h-5 w-5" />} title="Nothing to fix here" hint={`${report.healthy} of ${report.total} logins look healthy.`} /></div>
          ) : (
            <div className="card divide-y divide-slate-100 dark:divide-slate-800">
              {visible.map(({ item, issues }) => (
                <div key={item.id} className="flex flex-wrap items-center gap-3 px-4 py-3">
                  <div className="min-w-0 flex-1">
                    <Link to={`/vault?item=${item.id}`} className="font-medium hover:underline">{item.data.name}</Link>
                    <div className="truncate text-xs text-slate-500">{item.data.login?.username}</div>
                    <ul className="mt-1 space-y-0.5">
                      {issues.map((x, n) => <li key={n} className="text-xs text-slate-600 dark:text-slate-300">• {x.detail}</li>)}
                    </ul>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {[...new Set(issues.map((x) => x.kind))].map((k) => (
                      <span key={k} className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${KINDS[k].tone}`}>{KINDS[k].label}</span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}

      {showAccountBreaches && breaches?.status.accounts && (
        <section className="card p-5">
          <div className="flex items-center gap-3">
            <MailWarning className="h-5 w-5 text-slate-400" />
            <div className="flex-1">
              <h2 className="font-semibold">Is my e-mail in a data breach?</h2>
              <p className="text-sm text-slate-500">Checks your account e-mail against Have I Been Pwned.</p>
            </div>
            <button
              className="btn-secondary"
              onClick={() => myBreachedAccounts().then((accounts) => setBreaches((b) => b && { ...b, accounts }), (e) => toast(errorMessage(e), 'error'))}
            >
              Check
            </button>
          </div>
          {breaches.accounts && (
            breaches.accounts.length === 0 ? (
              <p className="mt-3 text-sm text-emerald-600">Good news: no known breaches.</p>
            ) : (
              <ul className="mt-3 divide-y divide-slate-100 text-sm dark:divide-slate-800">
                {breaches.accounts.map((b) => (
                  <li key={b.name} className="py-2">
                    <span className="font-medium">{b.name}</span> <span className="text-slate-500">({b.domain}, {b.breachDate})</span>
                    <div className="text-xs text-slate-500">Exposed: {b.dataClasses.join(', ')}</div>
                  </li>
                ))}
              </ul>
            )
          )}
        </section>
      )}
    </div>
  );
}

export function HealthPage() {
  const items = useSession((s) => s.items);
  // Masked ("use") items can't be inspected by the member, so they are excluded.
  const mine = useMemo(() => items.filter((i) => i.permission !== 'use'), [items]);
  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-5xl p-6">
        <h1 className="mb-1 flex items-center gap-2 text-lg font-semibold"><HeartPulse className="h-5 w-5 text-brand-600" /> Vault health</h1>
        <HealthView items={mine} scopeLabel="your personal vault and the shared items you can view" showAccountBreaches />
      </div>
    </div>
  );
}

