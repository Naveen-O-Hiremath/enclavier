import { useEffect, useState } from 'react';
import { Plus, Radio, Send, Trash2, Pencil } from 'lucide-react';
import { generatePassword } from '@enclavier/crypto';
import type { DestinationType, LogDestination } from '@enclavier/shared';
import { api } from '../../lib/api';
import { Modal, PasswordInput, Spinner } from '../../components/ui';
import { errorMessage, toast } from '../../components/Toast';
import { Badge, useOrgData } from './shared';

interface FieldSpec {
  key: string;
  label: string;
  kind?: 'text' | 'secret' | 'number' | 'select' | 'textarea';
  options?: string[];
  placeholder?: string;
  optional?: boolean;
  hint?: string;
}

const TYPES: Record<DestinationType, { label: string; blurb: string; fields: FieldSpec[]; defaults?: Record<string, unknown> }> = {
  splunk: {
    label: 'Splunk (HEC)',
    blurb: 'HTTP Event Collector, one JSON event per audit entry.',
    fields: [
      { key: 'url', label: 'HEC URL', placeholder: 'https://splunk.example.com:8088/services/collector/event' },
      { key: 'token', label: 'HEC token', kind: 'secret' },
      { key: 'index', label: 'Index', optional: true },
      { key: 'sourcetype', label: 'Sourcetype', optional: true, placeholder: 'enclavier:audit' },
    ],
  },
  sentinel: {
    label: 'Microsoft Sentinel',
    blurb: 'Azure Monitor Logs Ingestion API: an Entra app with the Monitoring Metrics Publisher role on the DCR.',
    fields: [
      { key: 'tenantId', label: 'Directory (tenant) ID' },
      { key: 'clientId', label: 'Application (client) ID' },
      { key: 'clientSecret', label: 'Client secret', kind: 'secret' },
      { key: 'endpoint', label: 'Data collection endpoint', placeholder: 'https://my-dce.westeurope-1.ingest.monitor.azure.com' },
      { key: 'dcrId', label: 'DCR immutable ID', placeholder: 'dcr-…' },
      { key: 'stream', label: 'Stream name', optional: true, placeholder: 'Custom-EnclavierAudit_CL' },
    ],
  },
  datadog: {
    label: 'Datadog',
    blurb: 'Logs intake API v2.',
    fields: [
      { key: 'site', label: 'Site', kind: 'select', options: ['datadoghq.com', 'datadoghq.eu', 'us3.datadoghq.com', 'us5.datadoghq.com', 'ap1.datadoghq.com', 'ddog-gov.com'] },
      { key: 'apiKey', label: 'API key', kind: 'secret' },
      { key: 'service', label: 'Service', optional: true, placeholder: 'enclavier' },
    ],
    defaults: { site: 'datadoghq.com' },
  },
  sumologic: {
    label: 'Sumo Logic',
    blurb: 'Hosted collector HTTP source.',
    fields: [{ key: 'url', label: 'HTTP source URL', kind: 'secret', placeholder: 'https://endpoint1.collection.sumologic.com/receiver/v1/http/…' }],
  },
  syslog: {
    label: 'Syslog (RFC 5424)',
    blurb: 'For QRadar, ArcSight, Graylog, rsyslog and on-prem SIEMs. TLS recommended.',
    fields: [
      { key: 'host', label: 'Host' },
      { key: 'port', label: 'Port', kind: 'number' },
      { key: 'protocol', label: 'Protocol', kind: 'select', options: ['tls', 'tcp', 'udp'] },
      { key: 'facility', label: 'Facility (16 = local0)', kind: 'number', optional: true },
      { key: 'caCert', label: 'Custom CA certificate (PEM)', kind: 'textarea', optional: true },
    ],
    defaults: { port: 6514, protocol: 'tls', facility: 16 },
  },
  webhook: {
    label: 'Webhook / SOAR',
    blurb: 'JSON batches signed with HMAC-SHA256 (X-Enclavier-Signature: t=…,v1=…).',
    fields: [
      { key: 'url', label: 'URL', placeholder: 'https://soar.example.com/hooks/enclavier' },
      { key: 'secret', label: 'Signing secret', kind: 'secret', hint: 'Verify HMAC_SHA256(secret, `${t}.${body}`) on the receiver.' },
    ],
  },
};

function DestinationDialog({ existing, onClose, onSaved }: { existing?: LogDestination; onClose: () => void; onSaved: () => void }) {
  const { orgId } = useOrgData();
  const [type, setType] = useState<DestinationType>(existing?.type ?? 'splunk');
  const [name, setName] = useState(existing?.name ?? '');
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [backfill, setBackfill] = useState(false);
  const [config, setConfig] = useState<Record<string, unknown>>(() =>
    existing ? existing.config : { ...TYPES.splunk.defaults },
  );
  const [busy, setBusy] = useState(false);
  const spec = TYPES[type];

  function pickType(t: DestinationType) {
    setType(t);
    setConfig({ ...TYPES[t].defaults, ...(t === 'webhook' ? { secret: generatePassword({ length: 40, lowercase: true, uppercase: true, digits: true, symbols: false, avoidAmbiguous: false }) } : {}) });
  }

  async function save() {
    setBusy(true);
    const clean: Record<string, unknown> = { type };
    for (const f of spec.fields) {
      const v = config[f.key];
      if (v === '' || v === undefined || v === null) continue;
      clean[f.key] = f.kind === 'number' ? Number(v) : v;
    }
    try {
      if (existing) await api('PUT', `/api/orgs/${orgId}/log-destinations/${existing.id}`, { name: name.trim(), enabled, config: clean });
      else await api('POST', `/api/orgs/${orgId}/log-destinations`, { name: name.trim(), backfill, config: clean });
      toast(existing ? 'Destination updated' : 'Destination added: events are delivered within seconds');
      onSaved();
      onClose();
    } catch (e) {
      toast(errorMessage(e), 'error');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      wide
      title={existing ? `Edit ${existing.name}` : 'Add log destination'}
      onClose={onClose}
      footer={
        <>
          <button className="btn-secondary" onClick={onClose}>Cancel</button>
          <button className="btn-primary" onClick={save} disabled={busy || !name.trim()}>{busy && <Spinner />} Save</button>
        </>
      }
    >
      <div className="space-y-4">
        {!existing && (
          <div className="grid gap-2 sm:grid-cols-3">
            {(Object.keys(TYPES) as DestinationType[]).map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => pickType(t)}
                className={`rounded-lg border p-2.5 text-left text-sm ${type === t ? 'border-brand-500 bg-brand-50 ring-2 ring-brand-500/20 dark:bg-brand-500/10' : 'border-slate-200 dark:border-slate-700'}`}
              >
                {TYPES[t].label}
              </button>
            ))}
          </div>
        )}
        <p className="text-xs text-slate-500">{spec.blurb}</p>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="sm:col-span-2">
            <label className="label">Name</label>
            <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder={`${spec.label} production`} />
          </div>
          {spec.fields.map((f) => {
            const value = config[f.key] === undefined ? '' : String(config[f.key]);
            const set = (v: string) => setConfig({ ...config, [f.key]: v });
            return (
              <div key={f.key} className={f.kind === 'textarea' || f.key === 'url' || f.key === 'endpoint' ? 'sm:col-span-2' : ''}>
                <label className="label">{f.label}{f.optional && <span className="normal-case"> (optional)</span>}</label>
                {f.kind === 'select' ? (
                  <select className="input" value={value} onChange={(e) => set(e.target.value)}>
                    {f.options!.map((o) => <option key={o} value={o}>{o}</option>)}
                  </select>
                ) : f.kind === 'secret' ? (
                  <PasswordInput mono value={value} onChange={set} placeholder={existing ? 'Leave unchanged to keep the stored value' : f.placeholder} />
                ) : f.kind === 'textarea' ? (
                  <textarea className="input min-h-24 font-mono text-xs" value={value} onChange={(e) => set(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" />
                ) : (
                  <input className="input" type={f.kind === 'number' ? 'number' : 'text'} value={value} onChange={(e) => set(e.target.value)} placeholder={f.placeholder} />
                )}
                {f.hint && <p className="mt-1 text-xs text-slate-500">{f.hint}</p>}
              </div>
            );
          })}
        </div>
        {existing ? (
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled</label>
        ) : (
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={backfill} onChange={(e) => setBackfill(e.target.checked)} /> Also send the organization's existing history</label>
        )}
        <p className="text-xs text-slate-500">Credentials are encrypted at rest on the server and never shown again after saving.</p>
      </div>
    </Modal>
  );
}

export function StreamingTab() {
  const { orgId } = useOrgData();
  const [list, setList] = useState<LogDestination[] | null>(null);
  const [editing, setEditing] = useState<LogDestination | 'new' | null>(null);
  const [testing, setTesting] = useState<string | null>(null);

  const reload = () => api<LogDestination[]>('GET', `/api/orgs/${orgId}/log-destinations`).then(setList, (e) => toast(errorMessage(e), 'error'));
  useEffect(() => {
    void reload();
    const t = setInterval(() => void reload(), 15_000);
    return () => clearInterval(t);
  }, [orgId]); // eslint-disable-line react-hooks/exhaustive-deps

  async function test(d: LogDestination) {
    setTesting(d.id);
    try {
      const r = await api<{ ok: boolean; message: string }>('POST', `/api/orgs/${orgId}/log-destinations/${d.id}/test`);
      toast(r.message, r.ok ? 'success' : 'error');
    } catch (e) {
      toast(errorMessage(e), 'error');
    } finally {
      setTesting(null);
    }
  }

  if (!list) return <Spinner className="h-6 w-6" />;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <p className="text-sm text-slate-500">Stream every audit event to your SIEM in near real time. Delivery is at-least-once, with retries; de-duplicate on the event <code>id</code>.</p>
        <button className="btn-primary shrink-0" onClick={() => setEditing('new')}><Plus className="h-4 w-4" /> Add destination</button>
      </div>
      {list.length === 0 ? (
        <div className="card flex flex-col items-center gap-2 p-10 text-center">
          <Radio className="h-6 w-6 text-slate-400" />
          <div className="font-medium">No destinations yet</div>
          <p className="max-w-md text-sm text-slate-500">Splunk, Microsoft Sentinel, Datadog, Sumo Logic, syslog or any webhook.</p>
        </div>
      ) : (
        <div className="card divide-y divide-slate-100 dark:divide-slate-800">
          {list.map((d) => (
            <div key={d.id} className="flex flex-wrap items-center gap-3 px-4 py-3">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-medium">{d.name}</span>
                  <span className="text-xs text-slate-500">{TYPES[d.type].label}</span>
                  {!d.enabled ? <Badge tone="slate">Paused</Badge> : d.failures > 0 ? <Badge tone="red">Failing</Badge> : <Badge tone="green">Healthy</Badge>}
                </div>
                <div className="text-xs text-slate-500">
                  {d.lastSuccessAt ? `Last delivery ${new Date(d.lastSuccessAt).toLocaleString()}` : 'No deliveries yet'}
                  {d.backlog > 0 && ` · ${d.backlog} event(s) queued`}
                </div>
                {d.lastError && <div className="mt-1 text-xs text-red-600">{d.lastError}</div>}
              </div>
              <button className="btn-secondary px-2.5 py-1 text-xs" onClick={() => test(d)} disabled={testing === d.id}>
                {testing === d.id ? <Spinner /> : <Send className="h-3.5 w-3.5" />} Send test
              </button>
              <button className="icon-btn" title="Edit" onClick={() => setEditing(d)}><Pencil className="h-4 w-4" /></button>
              <button
                className="icon-btn hover:text-red-600"
                title="Delete"
                onClick={() => api('DELETE', `/api/orgs/${orgId}/log-destinations/${d.id}`).then(() => { toast('Destination removed'); void reload(); }, (e) => toast(errorMessage(e), 'error'))}
              >
                <Trash2 className="h-4 w-4" />
              </button>
            </div>
          ))}
        </div>
      )}
      {editing && <DestinationDialog existing={editing === 'new' ? undefined : editing} onClose={() => setEditing(null)} onSaved={() => void reload()} />}
    </div>
  );
}
