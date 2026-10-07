import { useState, type ReactNode } from 'react';
import { LifeBuoy, ShieldCheck } from 'lucide-react';
import { setAccountRecovery, setRequire2fa } from '../../lib/security';
import { useSession } from '../../lib/session';
import { Modal, Spinner } from '../../components/ui';
import { errorMessage, toast } from '../../components/Toast';
import { useOrgData } from './shared';
import { MorePolicies } from './MorePolicies';

function Switch({ checked, onChange, disabled }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative h-5 w-9 shrink-0 rounded-full transition disabled:opacity-50 ${checked ? 'bg-brand-600' : 'bg-slate-300 dark:bg-slate-700'}`}
    >
      <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white shadow transition ${checked ? 'left-4.5' : 'left-0.5'}`} />
    </button>
  );
}

function PolicyCard(props: { icon: ReactNode; title: string; description: ReactNode; checked: boolean; busy: boolean; onChange: (v: boolean) => void; children?: ReactNode }) {
  return (
    <section className="card p-5">
      <div className="flex items-start gap-3">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-brand-50 text-brand-600 dark:bg-brand-500/10">{props.icon}</div>
        <div className="flex-1">
          <h2 className="font-semibold">{props.title}</h2>
          <div className="mt-0.5 text-sm text-slate-500">{props.description}</div>
          {props.children}
        </div>
        {props.busy ? <Spinner /> : <Switch checked={props.checked} onChange={props.onChange} />}
      </div>
    </section>
  );
}

export function PoliciesTab() {
  const { orgId, members, reload } = useOrgData();
  const org = useSession((s) => s.organizations.find((o) => o.id === orgId))!;
  const [busy, setBusy] = useState<string | null>(null);
  const [confirmOff, setConfirmOff] = useState(false);

  const without2fa = members.filter((m) => m.status === 'confirmed' && !m.revoked && !m.twoFactorEnabled);
  const enrolled = members.filter((m) => m.recoveryEnrolled).length;

  async function run(key: string, fn: () => Promise<unknown>, done: string) {
    setBusy(key);
    try {
      await fn();
      toast(done);
      await reload();
    } catch (e) {
      toast(errorMessage(e), 'error');
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-4">
      <PolicyCard
        icon={<ShieldCheck className="h-4 w-4" />}
        title="Require two-step login"
        description="Members without a security key or authenticator app lose access to shared items (and never receive the organization key) until they set one up."
        checked={org.policies.require2fa}
        busy={busy === '2fa'}
        onChange={(v) => run('2fa', () => setRequire2fa(orgId, v), v ? 'Two-step login is now required' : 'Requirement removed')}
      >
        {without2fa.length > 0 && (
          <p className="mt-2 text-xs text-amber-700 dark:text-amber-400">
            {without2fa.length} active member{without2fa.length === 1 ? ' has' : 's have'} no second factor yet:{' '}
            {without2fa.slice(0, 5).map((m) => m.email).join(', ')}
            {without2fa.length > 5 ? '…' : ''}
          </p>
        )}
      </PolicyCard>

      <PolicyCard
        icon={<LifeBuoy className="h-4 w-4" />}
        title="Account recovery (admin password reset)"
        description={
          <>
            Enrolled members' vault keys are sealed to an organization recovery key, so admins can reset a forgotten master password. This also
            lets admins open enrolled members' <strong>personal</strong> vaults, so enable it only if your policies require it.
          </>
        }
        checked={org.policies.accountRecovery}
        busy={busy === 'recovery'}
        onChange={(v) => (v ? run('recovery', () => setAccountRecovery(org, true, org.policies.accountRecoveryAutoEnroll), 'Account recovery enabled') : setConfirmOff(true))}
      >
        {org.policies.accountRecovery && (
          <div className="mt-3 space-y-2">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={org.policies.accountRecoveryAutoEnroll}
                disabled={!!busy}
                onChange={(e) => run('recovery', () => setAccountRecovery(org, true, e.target.checked), 'Policy updated')}
              />
              Enroll members automatically (they can't opt out)
            </label>
            <p className="text-xs text-slate-500">{enrolled} of {members.filter((m) => m.status === 'confirmed').length} members enrolled.</p>
          </div>
        )}
      </PolicyCard>

      <MorePolicies orgId={orgId} />

      {confirmOff && (
        <Modal
          title="Turn off account recovery?"
          onClose={() => setConfirmOff(false)}
          footer={
            <>
              <button className="btn-secondary" onClick={() => setConfirmOff(false)}>Cancel</button>
              <button
                className="btn-danger"
                onClick={() => {
                  setConfirmOff(false);
                  void run('recovery', () => setAccountRecovery(org, false, false), 'Account recovery turned off');
                }}
              >
                Turn off and delete enrollments
              </button>
            </>
          }
        >
          <p className="text-sm text-slate-600 dark:text-slate-300">
            All {enrolled} escrowed keys are deleted. Admins will no longer be able to reset anyone's master password, and members must enroll
            again if you turn it back on.
          </p>
        </Modal>
      )}
    </div>
  );
}
