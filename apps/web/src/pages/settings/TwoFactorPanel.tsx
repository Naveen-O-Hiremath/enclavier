import { useEffect, useState, type FormEvent } from 'react';
import QRCode from 'qrcode';
import { OtpInput } from '../../components/OtpInput';
import { Copy, Download, KeyRound, Plus, ShieldCheck, Smartphone, Trash2 } from 'lucide-react';
import { InvalidPasswordError } from '@enclavier/crypto';
import type { TotpSetupResponse, TwoFactorStatus } from '@enclavier/shared';
import {
  addSecurityKey,
  disableTotp,
  enableTotp,
  getTwoFactorStatus,
  regenerateRecoveryCodes,
  removeSecurityKey,
  startTotpSetup,
} from '../../lib/security';
import { useSession } from '../../lib/session';
import { copyWithToast, Modal, PasswordInput, Spinner } from '../../components/ui';
import { errorMessage, toast } from '../../components/Toast';

const friendly = (e: unknown) => {
  if (e instanceof InvalidPasswordError) return 'Master password is incorrect';
  const msg = errorMessage(e);
  return /NotAllowed|timed out/i.test(msg) ? 'The security key prompt was cancelled or timed out' : msg;
};

export function RecoveryCodesDialog({ codes, onClose }: { codes: string[]; onClose: () => void }) {
  const text = `Enclavier recovery codes\nGenerated ${new Date().toISOString()}\nEach code can be used once.\n\n${codes.join('\n')}\n`;
  function download() {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    a.download = 'enclavier-recovery-codes.txt';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }
  return (
    <Modal
      title="Save your recovery codes"
      onClose={onClose}
      footer={<button className="btn-primary" onClick={onClose}>I saved them</button>}
    >
      <p className="mb-4 text-sm text-slate-600 dark:text-slate-300">
        If you lose your phone or security key, a recovery code is the only way to sign in. Each works once. Store them somewhere safe
        and offline. They won't be shown again.
      </p>
      <div className="grid grid-cols-2 gap-2 rounded-lg bg-slate-50 p-4 font-mono text-sm dark:bg-slate-800/60">
        {codes.map((c) => <div key={c}>{c}</div>)}
      </div>
      <div className="mt-3 flex gap-2">
        <button className="btn-secondary" onClick={() => copyWithToast(codes.join('\n'), 'Recovery codes')}><Copy className="h-4 w-4" /> Copy</button>
        <button className="btn-secondary" onClick={download}><Download className="h-4 w-4" /> Download</button>
      </div>
    </Modal>
  );
}

function TotpSetupDialog({ onClose, onDone }: { onClose: () => void; onDone: (codes: string[] | null) => void }) {
  const [setup, setSetup] = useState<TotpSetupResponse | null>(null);
  const [qr, setQr] = useState('');
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    startTotpSetup().then(
      async (s) => {
        setSetup(s);
        setQr(await QRCode.toDataURL(s.uri, { margin: 1, width: 200 }));
      },
      (e) => {
        toast(friendly(e), 'error');
        onClose();
      },
    );
    // Run once per dialog: each call mints a new secret.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!setup) return;
    setBusy(true);
    try {
      const res = await enableTotp(setup.setupToken, code.replace(/\s/g, ''));
      toast('Authenticator app enabled');
      onDone(res.recoveryCodes);
    } catch (err) {
      toast(friendly(err), 'error');
      setCode('');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title="Set up an authenticator app" onClose={onClose}>
      {!setup ? (
        <Spinner className="h-6 w-6" />
      ) : (
        <form onSubmit={submit} className="space-y-4">
          <p className="text-sm text-slate-600 dark:text-slate-300">
            <span className="mr-2 inline-flex h-5 w-5 items-center justify-center rounded-full bg-brand-50 text-xs font-semibold text-brand-700 dark:bg-brand-500/10 dark:text-brand-400">1</span>
            Scan this code with Google Authenticator, Microsoft Authenticator, Authy or any authenticator app.
          </p>
          <div className="flex justify-center">{qr && <img src={qr} alt="Authenticator QR code" className="h-48 w-48 rounded-lg bg-white p-2" />}</div>
          <details className="text-xs text-slate-500">
            <summary className="cursor-pointer">Can't scan? Enter the key manually</summary>
            <code className="mt-2 block rounded bg-slate-100 p-2 font-mono break-all dark:bg-slate-800">{setup.secret.match(/.{1,4}/g)!.join(' ')}</code>
          </details>
          <div>
            <p className="mb-3 text-sm text-slate-600 dark:text-slate-300">
              <span className="mr-2 inline-flex h-5 w-5 items-center justify-center rounded-full bg-brand-50 text-xs font-semibold text-brand-700 dark:bg-brand-500/10 dark:text-brand-400">2</span>
              Enter the 6-digit code the app shows.
            </p>
            <OtpInput value={code} onChange={setCode} autoFocus disabled={busy} />
          </div>
          <div className="flex justify-end gap-2">
            <button type="button" className="btn-secondary" onClick={onClose}>Cancel</button>
            <button className="btn-primary" disabled={busy || code.replace(/\s/g, '').length !== 6}>{busy && <Spinner />} Enable</button>
          </div>
        </form>
      )}
    </Modal>
  );
}

function PasswordConfirmDialog(props: { title: string; body: string; action: string; onConfirm: (password: string) => Promise<void>; onClose: () => void }) {
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await props.onConfirm(password);
      props.onClose();
    } catch (err) {
      toast(friendly(err), 'error');
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal title={props.title} onClose={props.onClose}>
      <form onSubmit={submit} className="space-y-4">
        <p className="text-sm text-slate-600 dark:text-slate-300">{props.body}</p>
        <div>
          <label className="label">Master password</label>
          <PasswordInput value={password} onChange={setPassword} autoFocus autoComplete="current-password" />
        </div>
        <div className="flex justify-end gap-2">
          <button type="button" className="btn-secondary" onClick={props.onClose}>Cancel</button>
          <button className="btn-primary" disabled={busy || !password}>{busy && <Spinner />} {props.action}</button>
        </div>
      </form>
    </Modal>
  );
}

export function TwoFactorPanel() {
  const sync = useSession((s) => s.sync);
  const [status, setStatus] = useState<TwoFactorStatus | null>(null);
  const [dialog, setDialog] = useState<
    | { kind: 'totp' }
    | { kind: 'codes'; codes: string[] }
    | { kind: 'confirm'; title: string; body: string; action: string; run: (pw: string) => Promise<void> }
    | null
  >(null);
  const [keyName, setKeyName] = useState('');
  const [adding, setAdding] = useState(false);

  const reload = () => getTwoFactorStatus().then(setStatus, (e) => toast(friendly(e), 'error'));
  useEffect(() => void reload(), []);

  async function afterChange(codes: string[] | null) {
    await reload();
    await sync();
    setDialog(codes ? { kind: 'codes', codes } : null);
  }

  async function addKey() {
    setAdding(true);
    try {
      const codes = await addSecurityKey(keyName.trim() || 'Security key');
      toast('Security key added');
      setKeyName('');
      await afterChange(codes);
    } catch (err) {
      toast(friendly(err), 'error');
    } finally {
      setAdding(false);
    }
  }

  if (!status) return <Spinner />;
  const enabled = status.totpEnabled || status.webauthn.length > 0;

  return (
    <div className="space-y-5">
      <div className={`flex items-center gap-2 rounded-lg px-3 py-2 text-sm ${enabled ? 'bg-emerald-50 text-emerald-800 dark:bg-emerald-500/10 dark:text-emerald-300' : 'bg-amber-50 text-amber-800 dark:bg-amber-500/10 dark:text-amber-300'}`}>
        <ShieldCheck className="h-4 w-4" />
        {enabled ? 'Two-step login is on. A second factor is required on every new sign-in.' : 'Two-step login is off. Anyone with your master password can sign in.'}
      </div>

      <div className="flex items-start gap-3">
        <KeyRound className="mt-0.5 h-5 w-5 text-slate-400" />
        <div className="flex-1">
          <div className="text-sm font-medium">Security keys & passkeys <span className="ml-1 text-xs font-normal text-emerald-600">Phishing-resistant · recommended</span></div>
          <p className="text-xs text-slate-500">YubiKey and other FIDO2 keys, Windows Hello, Touch ID, or a passkey on your phone.</p>
          {status.webauthn.length > 0 && (
            <ul className="mt-2 divide-y divide-slate-100 rounded-lg border border-slate-200 dark:divide-slate-800 dark:border-slate-800">
              {status.webauthn.map((k) => (
                <li key={k.id} className="flex items-center gap-3 px-3 py-2">
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm">{k.name}{k.backedUp && <span className="ml-2 text-xs text-slate-400">synced passkey</span>}</div>
                    <div className="text-xs text-slate-500">
                      Added {new Date(k.createdAt).toLocaleDateString()} · {k.lastUsedAt ? `last used ${new Date(k.lastUsedAt).toLocaleDateString()}` : 'never used'}
                    </div>
                  </div>
                  <button
                    className="icon-btn hover:text-red-600"
                    title="Remove"
                    onClick={() => setDialog({ kind: 'confirm', title: `Remove ${k.name}?`, body: 'You will no longer be able to sign in with this key.', action: 'Remove', run: async (pw) => { await removeSecurityKey(k.id, pw); toast('Security key removed'); await afterChange(null); } })}
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </li>
              ))}
            </ul>
          )}
          <div className="mt-2 flex gap-2">
            <input className="input max-w-56 py-1.5" placeholder="Name, e.g. YubiKey 5C" maxLength={60} value={keyName} onChange={(e) => setKeyName(e.target.value)} />
            <button className="btn-secondary" onClick={addKey} disabled={adding}>{adding ? <Spinner /> : <Plus className="h-4 w-4" />} Add key</button>
          </div>
        </div>
      </div>

      <div className="flex items-start gap-3">
        <Smartphone className="mt-0.5 h-5 w-5 text-slate-400" />
        <div className="flex-1">
          <div className="text-sm font-medium">Authenticator app</div>
          <p className="text-xs text-slate-500">Time-based 6-digit codes (TOTP).</p>
        </div>
        {status.totpEnabled ? (
          <button
            className="btn-secondary"
            onClick={() => setDialog({ kind: 'confirm', title: 'Turn off authenticator app?', body: 'Confirm with your master password.', action: 'Turn off', run: async (pw) => { await disableTotp(pw); toast('Authenticator app removed'); await afterChange(null); } })}
          >
            Turn off
          </button>
        ) : (
          <button className="btn-secondary" onClick={() => setDialog({ kind: 'totp' })}>Set up</button>
        )}
      </div>

      {enabled && (
        <div className="flex items-center gap-3 border-t border-slate-100 pt-4 dark:border-slate-800">
          <div className="flex-1 text-sm">
            <div className="font-medium">Recovery codes</div>
            <div className={`text-xs ${status.recoveryCodesRemaining <= 3 ? 'text-amber-600' : 'text-slate-500'}`}>{status.recoveryCodesRemaining} of 10 unused</div>
          </div>
          <button
            className="btn-secondary"
            onClick={() => setDialog({ kind: 'confirm', title: 'Generate new recovery codes?', body: 'Your existing recovery codes will stop working.', action: 'Generate', run: async (pw) => { const codes = await regenerateRecoveryCodes(pw); await reload(); setTimeout(() => setDialog({ kind: 'codes', codes })); } })}
          >
            Generate new codes
          </button>
        </div>
      )}

      {dialog?.kind === 'totp' && <TotpSetupDialog onClose={() => setDialog(null)} onDone={(codes) => void afterChange(codes)} />}
      {dialog?.kind === 'codes' && <RecoveryCodesDialog codes={dialog.codes} onClose={() => setDialog(null)} />}
      {dialog?.kind === 'confirm' && (
        <PasswordConfirmDialog title={dialog.title} body={dialog.body} action={dialog.action} onConfirm={dialog.run} onClose={() => setDialog((d) => (d?.kind === 'confirm' ? null : d))} />
      )}
    </div>
  );
}
