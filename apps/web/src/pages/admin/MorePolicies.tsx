import { useState, type ReactNode } from 'react';
import { ClipboardX, FileLock2, KeyRound, TimerReset, Wand2 } from 'lucide-react';
import type { OrgPolicies, UpdatePolicyRequest } from '@enclavier/shared';
import { api } from '../../lib/api';
import { useSession } from '../../lib/session';
import { SCORE_LABELS } from '../../lib/strength';
import { Spinner } from '../../components/ui';
import { errorMessage, toast } from '../../components/Toast';

function Card(props: { icon: ReactNode; title: string; description: string; enabled: boolean; busy: boolean; onToggle: (v: boolean) => void; children?: ReactNode }) {
  return (
    <section className="card p-5">
      <div className="flex items-start gap-3">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-brand-50 text-brand-600 dark:bg-brand-500/10">{props.icon}</div>
        <div className="flex-1">
          <h2 className="font-semibold">{props.title}</h2>
          <p className="mt-0.5 text-sm text-slate-500">{props.description}</p>
          {props.enabled && props.children && <div className="mt-3 flex flex-wrap items-end gap-3">{props.children}</div>}
        </div>
        {props.busy ? (
          <Spinner />
        ) : (
          <button
            type="button"
            role="switch"
            aria-checked={props.enabled}
            onClick={() => props.onToggle(!props.enabled)}
            className={`relative h-5 w-9 shrink-0 rounded-full transition ${props.enabled ? 'bg-brand-600' : 'bg-slate-300 dark:bg-slate-700'}`}
          >
            <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white shadow transition ${props.enabled ? 'left-4.5' : 'left-0.5'}`} />
          </button>
        )}
      </div>
    </section>
  );
}

function NumberField({ label, value, min, max, onCommit }: { label: string; value: number; min: number; max: number; onCommit: (v: number) => void }) {
  const [v, setV] = useState(String(value));
  const commit = () => {
    const n = Math.min(max, Math.max(min, Number(v) || min));
    setV(String(n));
    if (n !== value) onCommit(n);
  };
  return (
    <div>
      <label className="label">{label}</label>
      <input className="input w-28" type="number" min={min} max={max} value={v} onChange={(e) => setV(e.target.value)} onBlur={commit} onKeyDown={(e) => e.key === 'Enter' && commit()} />
    </div>
  );
}

/** Policy-engine cards: master password, generator, vault timeout, clipboard, export. */
export function MorePolicies({ orgId }: { orgId: string }) {
  const org = useSession((s) => s.organizations.find((o) => o.id === orgId))!;
  const sync = useSession((s) => s.sync);
  const [busy, setBusy] = useState<string | null>(null);
  const p: OrgPolicies = org.policies;

  async function save(body: UpdatePolicyRequest) {
    setBusy(body.type);
    try {
      await api('PUT', `/api/orgs/${orgId}/policies`, body);
      await sync();
      toast('Policy saved');
    } catch (e) {
      toast(errorMessage(e), 'error');
    } finally {
      setBusy(null);
    }
  }

  const mp = p.masterPassword ?? { minLength: 14, minScore: 3 };
  const gen = p.passwordGenerator ?? { minLength: 16, requireUppercase: true, requireLowercase: true, requireDigits: true, requireSymbols: false };
  const vt = p.vaultTimeout ?? { maxMinutes: 15 };
  const cb = p.clipboard ?? { maxSeconds: 30 };

  return (
    <>
      <Card
        icon={<KeyRound className="h-4 w-4" />}
        title="Master password requirements"
        description="Checked in each member's browser when they unlock (the server never sees master passwords). Members below the bar must change their password before continuing."
        enabled={!!p.masterPassword}
        busy={busy === 'master_password'}
        onToggle={(enabled) => save({ type: 'master_password', enabled, ...mp })}
      >
        <NumberField label="Minimum length" value={mp.minLength} min={8} max={128} onCommit={(minLength) => save({ type: 'master_password', enabled: true, ...mp, minLength })} />
        <div>
          <label className="label">Minimum strength</label>
          <select className="input w-40" value={mp.minScore} onChange={(e) => save({ type: 'master_password', enabled: true, ...mp, minScore: Number(e.target.value) })}>
            {SCORE_LABELS.map((l, i) => <option key={l} value={i}>{i}: {l}</option>)}
          </select>
        </div>
      </Card>

      <Card
        icon={<Wand2 className="h-4 w-4" />}
        title="Password generator minimums"
        description="Members' generators never produce passwords shorter or simpler than this."
        enabled={!!p.passwordGenerator}
        busy={busy === 'password_generator'}
        onToggle={(enabled) => save({ type: 'password_generator', enabled, ...gen })}
      >
        <NumberField label="Minimum length" value={gen.minLength} min={8} max={128} onCommit={(minLength) => save({ type: 'password_generator', enabled: true, ...gen, minLength })} />
        {(['requireUppercase', 'requireLowercase', 'requireDigits', 'requireSymbols'] as const).map((k) => (
          <label key={k} className="flex items-center gap-1.5 pb-2 text-sm">
            <input type="checkbox" checked={gen[k]} onChange={(e) => save({ type: 'password_generator', enabled: true, ...gen, [k]: e.target.checked })} />
            {{ requireUppercase: 'A–Z', requireLowercase: 'a–z', requireDigits: '0–9', requireSymbols: '!@#' }[k]}
          </label>
        ))}
      </Card>

      <Card
        icon={<TimerReset className="h-4 w-4" />}
        title="Maximum vault timeout"
        description="Vaults lock automatically after this much inactivity; members can choose shorter, never longer (PCI DSS 8.2.8: 15 minutes)."
        enabled={!!p.vaultTimeout}
        busy={busy === 'vault_timeout'}
        onToggle={(enabled) => save({ type: 'vault_timeout', enabled, ...vt })}
      >
        <NumberField label="Minutes" value={vt.maxMinutes} min={1} max={1440} onCommit={(maxMinutes) => save({ type: 'vault_timeout', enabled: true, maxMinutes })} />
      </Card>

      <Card
        icon={<ClipboardX className="h-4 w-4" />}
        title="Clipboard clearing"
        description="Copied passwords and codes are wiped from the clipboard within this time."
        enabled={!!p.clipboard}
        busy={busy === 'clipboard'}
        onToggle={(enabled) => save({ type: 'clipboard', enabled, ...cb })}
      >
        <NumberField label="Seconds" value={cb.maxSeconds} min={5} max={600} onCommit={(maxSeconds) => save({ type: 'clipboard', enabled: true, maxSeconds })} />
      </Card>

      <Card
        icon={<FileLock2 className="h-4 w-4" />}
        title="Disable vault export"
        description="Members cannot download a plaintext export of their personal vault. Organization items are never exportable."
        enabled={p.disableExport}
        busy={busy === 'disable_export'}
        onToggle={(enabled) => save({ type: 'disable_export', enabled })}
      />
    </>
  );
}
