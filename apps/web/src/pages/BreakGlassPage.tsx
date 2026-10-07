import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { Plus, ShieldAlert, Trash2 } from 'lucide-react';
import { decodeShare } from '@enclavier/crypto';
import { breakGlassRecover } from '../lib/security';
import { Spinner } from '../components/ui';
import { errorMessage, toast } from '../components/Toast';

/** /recover-org: share holders combine their shares to restore owner access to an organization. */
export function BreakGlassPage() {
  const navigate = useNavigate();
  const [orgId, setOrgId] = useState('');
  const [shares, setShares] = useState(['', '']);
  const [busy, setBusy] = useState(false);

  const parsed = shares.map((s) => {
    if (!s.trim()) return null;
    try {
      return decodeShare(s);
    } catch (e) {
      return e as Error;
    }
  });
  const threshold = parsed.find((p) => p && !(p instanceof Error)) as ReturnType<typeof decodeShare> | undefined;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const name = await breakGlassRecover(orgId.trim(), shares.filter((s) => s.trim()));
      toast(`You are now an owner of ${name}`);
      navigate(`/orgs/${orgId.trim()}`);
    } catch (err) {
      toast(errorMessage(err), 'error');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-2xl p-6">
      <div className="mb-6 flex items-center gap-3">
        <ShieldAlert className="h-6 w-6 text-red-600" />
        <div>
          <h1 className="text-lg font-semibold">Break-glass organization recovery</h1>
          <p className="text-sm text-slate-500">For use when every owner has lost access. Recovery makes you an owner, and all current owners are e-mailed.</p>
        </div>
      </div>
      <form onSubmit={submit} className="card space-y-4 p-5">
        <div>
          <label className="label">Organization ID</label>
          <input className="input font-mono" placeholder="Printed on each share sheet" value={orgId} onChange={(e) => setOrgId(e.target.value)} />
        </div>
        <div className="space-y-2">
          <label className="label">Recovery shares {threshold && `(${threshold.threshold} needed)`}</label>
          {shares.map((s, i) => {
            const p = parsed[i];
            return (
              <div key={i}>
                <div className="flex gap-2">
                  <textarea
                    className="input min-h-14 font-mono text-xs"
                    placeholder="ENCLAVIER-SHARE-1…"
                    value={s}
                    onChange={(e) => setShares(shares.map((x, j) => (j === i ? e.target.value : x)))}
                  />
                  {shares.length > 2 && (
                    <button type="button" className="icon-btn" onClick={() => setShares(shares.filter((_, j) => j !== i))} aria-label="Remove share">
                      <Trash2 className="h-4 w-4" />
                    </button>
                  )}
                </div>
                {p instanceof Error && <p className="mt-1 text-xs text-red-600">{p.message}</p>}
                {p && !(p instanceof Error) && <p className="mt-1 text-xs text-emerald-600">Share #{p.share.x} of kit {p.kitId}: checksum OK</p>}
              </div>
            );
          })}
          <button type="button" className="btn-ghost px-2 py-1 text-xs" onClick={() => setShares([...shares, ''])}>
            <Plus className="h-3.5 w-3.5" /> Add share
          </button>
        </div>
        <button className="btn-danger" disabled={busy || !orgId.trim() || parsed.some((p) => p instanceof Error) || parsed.filter(Boolean).length < 2}>
          {busy && <Spinner />} Recover organization
        </button>
      </form>
    </div>
  );
}
