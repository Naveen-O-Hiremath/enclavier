import { useEffect, useState } from 'react';
import { Copy, Download, KeySquare } from 'lucide-react';
import type { RecoveryKitInfo } from '@enclavier/shared';
import { createRecoveryKit, deleteRecoveryKit, getRecoveryKit } from '../../lib/security';
import { copyWithToast, Modal, Spinner } from '../../components/ui';
import { errorMessage, toast } from '../../components/Toast';

/** Owners split the org key into printed shares held by separate officers (break-glass). */
export function RecoveryKitPanel({ orgId, orgName, isOwner }: { orgId: string; orgName: string; isOwner: boolean }) {
  const [info, setInfo] = useState<RecoveryKitInfo | null>(null);
  const [shares, setShares] = useState(5);
  const [threshold, setThreshold] = useState(3);
  const [created, setCreated] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);

  const reload = () => getRecoveryKit(orgId).then(setInfo, (e) => toast(errorMessage(e), 'error'));
  useEffect(() => void reload(), [orgId]);

  async function create() {
    setBusy(true);
    try {
      setCreated(await createRecoveryKit(orgId, shares, threshold));
      await reload();
    } catch (e) {
      toast(errorMessage(e), 'error');
    } finally {
      setBusy(false);
    }
  }

  function downloadShare(text: string, n: number) {
    const body = [
      `ENCLAVIER BREAK-GLASS RECOVERY SHARE ${n} of ${created!.length}`,
      `Organization: ${orgName} (${orgId})`,
      `Any ${threshold} shares restore owner access at <your vault URL>/recover-org.`,
      'Keep this sheet sealed and separate from the other shares.',
      '',
      text,
      '',
    ].join('\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([body], { type: 'text/plain' }));
    a.download = `enclavier-${orgName.replace(/\W+/g, '-').toLowerCase()}-share-${n}.txt`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  if (!info) return <Spinner />;

  return (
    <section className="card p-5">
      <div className="flex items-start gap-3">
        <KeySquare className="mt-0.5 h-5 w-5 text-slate-400" />
        <div className="flex-1">
          <h2 className="font-semibold">Break-glass recovery kit</h2>
          <p className="mt-0.5 text-sm text-slate-500">
            Splits the organization key into shares with Shamir's Secret Sharing. If every owner loses access, any <em>k</em> share holders can
            restore owner access together. Fewer shares reveal nothing. The server stores only a one-way verifier.
          </p>
          {info.exists && (
            <p className="mt-2 text-sm">
              Active kit: <strong>{info.threshold} of {info.shares}</strong> shares, created {new Date(info.createdAt!).toLocaleDateString()}.
            </p>
          )}
          {isOwner ? (
            <div className="mt-4 flex flex-wrap items-end gap-3">
              <div>
                <label className="label">Shares</label>
                <input className="input w-24" type="number" min={2} max={20} value={shares} onChange={(e) => setShares(Math.max(2, Math.min(20, Number(e.target.value))))} />
              </div>
              <div>
                <label className="label">Needed to recover</label>
                <input className="input w-24" type="number" min={2} max={shares} value={threshold} onChange={(e) => setThreshold(Math.max(2, Math.min(shares, Number(e.target.value))))} />
              </div>
              <button className="btn-primary" disabled={busy} onClick={create}>{busy && <Spinner />} {info.exists ? 'Replace kit' : 'Create kit'}</button>
              {info.exists && (
                <button className="btn-secondary" disabled={busy} onClick={() => deleteRecoveryKit(orgId).then(() => { toast('Recovery kit deleted'); void reload(); }, (e) => toast(errorMessage(e), 'error'))}>
                  Delete kit
                </button>
              )}
            </div>
          ) : (
            <p className="mt-3 text-xs text-slate-500">Only owners can create or replace the kit.</p>
          )}
        </div>
      </div>

      {created && (
        <Modal wide title={`Recovery kit: ${threshold} of ${created.length}`} onClose={() => setCreated(null)} footer={<button className="btn-primary" onClick={() => setCreated(null)}>Done</button>}>
          <p className="mb-4 text-sm text-slate-600 dark:text-slate-300">
            Give each share to a different trusted officer, printed or on separate offline media. <strong>They are shown only once.</strong> Any
            previous kit has stopped working.
          </p>
          <div className="space-y-2">
            {created.map((s, i) => (
              <div key={i} className="flex items-center gap-2 rounded-lg border border-slate-200 p-2 dark:border-slate-800">
                <span className="w-16 shrink-0 text-xs font-medium text-slate-500">Share {i + 1}</span>
                <code className="min-w-0 flex-1 truncate font-mono text-xs">{s}</code>
                <button className="icon-btn" title="Copy" onClick={() => copyWithToast(s, `Share ${i + 1}`)}><Copy className="h-4 w-4" /></button>
                <button className="icon-btn" title="Download" onClick={() => downloadShare(s, i + 1)}><Download className="h-4 w-4" /></button>
              </div>
            ))}
          </div>
        </Modal>
      )}
    </section>
  );
}
