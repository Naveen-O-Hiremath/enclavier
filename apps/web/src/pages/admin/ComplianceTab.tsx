import { useEffect, useState } from 'react';
import { CheckCircle2, CircleAlert, Info, Printer, RefreshCw, XCircle } from 'lucide-react';
import type { ComplianceReport, ControlStatus, Framework } from '@enclavier/shared';
import { api } from '../../lib/api';
import { Spinner } from '../../components/ui';
import { errorMessage, toast } from '../../components/Toast';
import { useOrgData } from './shared';

const STATUS: Record<ControlStatus, { label: string; icon: typeof CheckCircle2; color: string }> = {
  pass: { label: 'Pass', icon: CheckCircle2, color: 'text-emerald-600' },
  warn: { label: 'Attention', icon: CircleAlert, color: 'text-amber-600' },
  fail: { label: 'Fail', icon: XCircle, color: 'text-red-600' },
  info: { label: 'Info', icon: Info, color: 'text-slate-500' },
};

export function ComplianceTab() {
  const { orgId } = useOrgData();
  const [report, setReport] = useState<ComplianceReport | null>(null);
  const [framework, setFramework] = useState<Framework | null>(null);
  const [loading, setLoading] = useState(false);

  async function load() {
    setLoading(true);
    try {
      setReport(await api<ComplianceReport>('GET', `/api/orgs/${orgId}/compliance`));
    } catch (e) {
      toast(errorMessage(e), 'error');
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => void load(), [orgId]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!report) return <Spinner className="h-6 w-6" />;
  const controls = report.controls.filter((c) => !framework || c.references.some((r) => r.framework === framework));

  return (
    <div className="compliance-report space-y-5">
      <div className="flex flex-wrap items-start gap-3">
        <div className="flex-1">
          <h2 className="text-lg font-semibold">Security posture: {report.organization.name}</h2>
          <p className="text-xs text-slate-500">
            Generated {new Date(report.generatedAt).toLocaleString()} by {report.generatedBy}
            {report.auditChainHead && <> · audit chain head #{report.auditChainHead.seq} <code className="font-mono">{report.auditChainHead.hash.slice(0, 16)}…</code></>}
          </p>
        </div>
        <div className="flex gap-2 print:hidden">
          <button className="btn-secondary" onClick={load} disabled={loading}>{loading ? <Spinner /> : <RefreshCw className="h-4 w-4" />} Refresh</button>
          <button className="btn-secondary" onClick={() => window.print()}><Printer className="h-4 w-4" /> Print / PDF</button>
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-5">
        {report.frameworks.map((f) => {
          const pct = f.total ? Math.round((f.pass / f.total) * 100) : 0;
          return (
            <button
              key={f.framework}
              onClick={() => setFramework(framework === f.framework ? null : f.framework)}
              className={`card p-3 text-left transition ${framework === f.framework ? 'ring-2 ring-brand-500' : ''}`}
            >
              <div className="text-xs font-medium text-slate-500">{f.framework}</div>
              <div className="mt-1 text-xl font-semibold">{pct}%</div>
              <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                <div className={`h-full rounded-full ${pct === 100 ? 'bg-emerald-500' : pct >= 60 ? 'bg-amber-500' : 'bg-red-500'}`} style={{ width: `${pct}%` }} />
              </div>
              <div className="mt-1 text-[11px] text-slate-500">{f.pass} of {f.total} controls</div>
            </button>
          );
        })}
      </div>

      <div className="card divide-y divide-slate-100 dark:divide-slate-800">
        {controls.map((c) => {
          const S = STATUS[c.status];
          return (
            <div key={c.id} className="flex gap-3 px-4 py-3.5">
              <S.icon className={`mt-0.5 h-5 w-5 shrink-0 ${S.color}`} />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-baseline gap-2">
                  <span className="font-medium">{c.title}</span>
                  <span className={`text-xs font-medium ${S.color}`}>{S.label}</span>
                </div>
                <p className="mt-0.5 text-sm text-slate-600 dark:text-slate-300">{c.evidence}</p>
                {c.recommendation && <p className="mt-1 text-sm text-brand-700 dark:text-brand-400">→ {c.recommendation}</p>}
                <div className="mt-1.5 flex flex-wrap gap-1">
                  {c.references.map((r) => (
                    <span key={`${r.framework}-${r.control}`} className="rounded bg-slate-100 px-1.5 py-0.5 text-[11px] text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                      {r.framework} {r.control}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          );
        })}
      </div>
      <p className="text-xs text-slate-500">{report.disclaimer}</p>
    </div>
  );
}
