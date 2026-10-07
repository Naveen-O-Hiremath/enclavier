import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { Check, Copy, Globe, KeyRound, Laptop, Plus, RefreshCw, Trash2, X } from 'lucide-react';
import { fingerprint, fromB64 } from '@enclavier/crypto';
import type { AdminDeviceRequest, ScimToken, SsoAdminView, SsoConfigUpdate } from '@enclavier/shared';
import {
  addDomain,
  approveDeviceRequest,
  createScimToken,
  denyDeviceRequest,
  getSso,
  listDeviceRequests,
  listScimTokens,
  removeDomain,
  revokeScimToken,
  saveSso,
  verifyDomain,
} from '../../lib/identity';
import { useSession } from '../../lib/session';
import { Modal, Spinner } from '../../components/ui';
import { errorMessage, toast } from '../../components/Toast';
import { Badge, useOrgData } from './shared';

function Section({ title, description, children, action }: { title: string; description: ReactNode; children: ReactNode; action?: ReactNode }) {
  return (
    <section className="card p-5">
      <div className="flex items-start gap-3">
        <div className="flex-1">
          <h2 className="font-semibold">{title}</h2>
          <div className="mt-0.5 text-sm text-slate-500">{description}</div>
        </div>
        {action}
      </div>
      <div className="mt-4">{children}</div>
    </section>
  );
}

function CopyField({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="label">{label}</div>
      <div className="flex items-center gap-2">
        <code className="min-w-0 flex-1 truncate rounded-lg bg-slate-100 px-3 py-2 text-xs dark:bg-slate-800">{value}</code>
        <button
          type="button"
          className="icon-btn"
          title="Copy"
          onClick={() => navigator.clipboard.writeText(value).then(() => toast(`${label} copied`), () => toast('Copy failed', 'error'))}
        >
          <Copy className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}

function Toggle({ checked, onChange, label, hint, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; hint: string; disabled?: boolean }) {
  return (
    <label className="flex items-start gap-3 text-sm">
      <input type="checkbox" className="mt-1" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span>
        <span className="font-medium">{label}</span>
        <span className="block text-xs text-slate-500">{hint}</span>
      </span>
    </label>
  );
}

type Form = {
  enabled: boolean;
  identifier: string;
  jitProvisioning: boolean;
  enforce: boolean;
  groupSync: boolean;
  type: 'oidc' | 'saml';
  issuer: string;
  clientId: string;
  clientSecret: string;
  scopes: string;
  emailClaim: string;
  groupsClaim: string;
  idpEntityId: string;
  ssoUrl: string;
  certificate: string;
  emailAttribute: string;
  nameAttribute: string;
  groupsAttribute: string;
};

function toForm(view: SsoAdminView, orgName: string): Form {
  const c = view.config;
  const s = (c?.settings ?? {}) as Record<string, string>;
  return {
    enabled: c?.enabled ?? false,
    identifier: c?.identifier ?? orgName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 63),
    jitProvisioning: c?.jitProvisioning ?? true,
    enforce: c?.enforce ?? false,
    groupSync: c?.groupSync ?? false,
    type: (s.type as Form['type']) ?? 'oidc',
    issuer: s.issuer ?? '',
    clientId: s.clientId ?? '',
    clientSecret: s.clientSecret ?? '',
    scopes: s.scopes ?? 'openid email profile',
    emailClaim: s.emailClaim ?? 'email',
    groupsClaim: s.groupsClaim ?? '',
    idpEntityId: s.idpEntityId ?? '',
    ssoUrl: s.ssoUrl ?? '',
    certificate: s.certificate ?? '',
    emailAttribute: s.emailAttribute ?? '',
    nameAttribute: s.nameAttribute ?? '',
    groupsAttribute: s.groupsAttribute ?? '',
  };
}

function toUpdate(f: Form): SsoConfigUpdate {
  const settings: SsoConfigUpdate['settings'] =
    f.type === 'oidc'
      ? { type: 'oidc', issuer: f.issuer, clientId: f.clientId, clientSecret: f.clientSecret || undefined, scopes: f.scopes, emailClaim: f.emailClaim || 'email', groupsClaim: f.groupsClaim }
      : { type: 'saml', idpEntityId: f.idpEntityId, ssoUrl: f.ssoUrl, certificate: f.certificate, emailAttribute: f.emailAttribute, nameAttribute: f.nameAttribute, groupsAttribute: f.groupsAttribute };
  return { enabled: f.enabled, identifier: f.identifier, jitProvisioning: f.jitProvisioning, enforce: f.enforce, groupSync: f.groupSync, settings };
}

function Field(props: { label: string; value: string; onChange: (v: string) => void; placeholder?: string; hint?: string; disabled?: boolean; mono?: boolean }) {
  return (
    <div>
      <label className="label">{props.label}</label>
      <input
        className={`input ${props.mono ? 'font-mono text-xs' : ''}`}
        value={props.value}
        placeholder={props.placeholder}
        disabled={props.disabled}
        onChange={(e) => props.onChange(e.target.value)}
      />
      {props.hint && <p className="mt-1 text-xs text-slate-500">{props.hint}</p>}
    </div>
  );
}

export function SsoTab() {
  const { orgId } = useOrgData();
  const org = useSession((s) => s.organizations.find((o) => o.id === orgId))!;
  const isOwner = org.role === 'owner';
  const [view, setView] = useState<SsoAdminView | null>(null);
  const [form, setForm] = useState<Form | null>(null);
  const [tokens, setTokens] = useState<ScimToken[]>([]);
  const [requests, setRequests] = useState<AdminDeviceRequest[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [newDomain, setNewDomain] = useState('');
  const [newToken, setNewToken] = useState<ScimToken | null>(null);
  const [reviewing, setReviewing] = useState<AdminDeviceRequest | null>(null);

  const load = useCallback(async () => {
    try {
      const [v, t, r] = await Promise.all([getSso(orgId), listScimTokens(orgId), listDeviceRequests(orgId)]);
      setView(v);
      setForm((f) => f ?? toForm(v, org.name));
      setTokens(t);
      setRequests(r);
    } catch (e) {
      toast(errorMessage(e), 'error');
    }
  }, [orgId, org.name]);
  useEffect(() => void load(), [load]);

  async function run(key: string, fn: () => Promise<unknown>, done?: string) {
    setBusy(key);
    try {
      await fn();
      if (done) toast(done);
      await load();
    } catch (e) {
      toast(errorMessage(e), 'error');
    } finally {
      setBusy(null);
    }
  }

  if (!view || !form) return <Spinner />;
  const set = (patch: Partial<Form>) => setForm({ ...form, ...patch });
  const sp = view.serviceProvider;
  const ownerOnly = !isOwner;

  return (
    <div className="space-y-4">
      {requests.length > 0 && (
        <Section title="Device approvals" description="Members signed in with SSO on a new device and asked an administrator to unlock it. Compare the phrase with the member before approving.">
          <ul className="divide-y divide-slate-100 dark:divide-slate-800">
            {requests.map((r) => (
              <li key={r.id} className="flex items-center gap-3 py-3">
                <Laptop className="h-5 w-5 text-slate-400" />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium">{r.name} · {r.email}</div>
                  <div className="truncate text-xs text-slate-500">{r.deviceName} · {new Date(r.createdAt).toLocaleString()}</div>
                </div>
                <button className="btn-primary text-xs" onClick={() => setReviewing(r)}>Review</button>
              </li>
            ))}
          </ul>
        </Section>
      )}

      <Section
        title="Single sign-on"
        description="Let members sign in with Okta, Microsoft Entra ID, Google Workspace, Ping, OneLogin, Keycloak or any SAML 2.0 / OpenID Connect provider. SSO proves who someone is. Their vault still opens only with their master password or on a trusted device."
        action={form.enabled ? <Badge tone="green">On</Badge> : <Badge tone="slate">Off</Badge>}
      >
        {ownerOnly && <p className="mb-4 rounded-lg bg-slate-50 p-3 text-xs text-slate-500 dark:bg-slate-800/50">Only owners can change single sign-on settings.</p>}
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Organization identifier" value={form.identifier} onChange={(v) => set({ identifier: v.toLowerCase() })} disabled={ownerOnly} hint="Members can type this on the SSO page if their domain isn't verified." />
          <div>
            <label className="label">Protocol</label>
            <div className="flex gap-2">
              {(['oidc', 'saml'] as const).map((t) => (
                <button key={t} type="button" disabled={ownerOnly} className={form.type === t ? 'btn-primary flex-1' : 'btn-secondary flex-1'} onClick={() => set({ type: t })}>
                  {t === 'oidc' ? 'OpenID Connect' : 'SAML 2.0'}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="mt-5 rounded-lg border border-slate-200 p-4 dark:border-slate-800">
          <p className="mb-3 text-xs font-medium tracking-wide text-slate-500 uppercase">Give these to your identity provider</p>
          <div className="grid gap-3">
            {form.type === 'oidc' ? (
              <CopyField label="Redirect (callback) URI" value={sp.redirectUri} />
            ) : (
              <>
                <CopyField label="Entity ID (audience)" value={sp.entityId} />
                <CopyField label="ACS URL (reply URL)" value={sp.acsUrl} />
                <CopyField label="SP metadata URL" value={sp.metadataUrl} />
              </>
            )}
          </div>
        </div>

        <div className="mt-5 grid gap-4 sm:grid-cols-2">
          {form.type === 'oidc' ? (
            <>
              <Field label="Issuer URL" value={form.issuer} onChange={(v) => set({ issuer: v })} disabled={ownerOnly} placeholder="https://login.microsoftonline.com/<tenant>/v2.0" />
              <Field label="Client ID" value={form.clientId} onChange={(v) => set({ clientId: v })} disabled={ownerOnly} />
              <Field label="Client secret" value={form.clientSecret} onChange={(v) => set({ clientSecret: v })} disabled={ownerOnly} hint="Stored encrypted. Leave the masked value to keep it." />
              <Field label="Scopes" value={form.scopes} onChange={(v) => set({ scopes: v })} disabled={ownerOnly} />
              <Field label="E-mail claim" value={form.emailClaim} onChange={(v) => set({ emailClaim: v })} disabled={ownerOnly} hint="Entra ID often needs preferred_username." />
              <Field label="Groups claim (optional)" value={form.groupsClaim} onChange={(v) => set({ groupsClaim: v })} disabled={ownerOnly} placeholder="groups" />
            </>
          ) : (
            <>
              <Field label="IdP entity ID (issuer)" value={form.idpEntityId} onChange={(v) => set({ idpEntityId: v })} disabled={ownerOnly} />
              <Field label="IdP sign-on URL" value={form.ssoUrl} onChange={(v) => set({ ssoUrl: v })} disabled={ownerOnly} placeholder="https://idp.example.com/sso/saml" />
              <div className="sm:col-span-2">
                <label className="label">IdP signing certificate (PEM)</label>
                <textarea
                  className="input h-28 font-mono text-xs"
                  value={form.certificate}
                  disabled={ownerOnly}
                  placeholder="-----BEGIN CERTIFICATE-----"
                  onChange={(e) => set({ certificate: e.target.value })}
                />
                <p className="mt-1 text-xs text-slate-500">Assertions must be signed with this certificate. Paste two to rotate without downtime.</p>
              </div>
              <Field label="E-mail attribute (optional)" value={form.emailAttribute} onChange={(v) => set({ emailAttribute: v })} disabled={ownerOnly} hint="Empty uses the NameID." mono />
              <Field label="Name attribute (optional)" value={form.nameAttribute} onChange={(v) => set({ nameAttribute: v })} disabled={ownerOnly} mono />
              <Field label="Groups attribute (optional)" value={form.groupsAttribute} onChange={(v) => set({ groupsAttribute: v })} disabled={ownerOnly} mono />
            </>
          )}
        </div>

        <div className="mt-5 space-y-3">
          <Toggle checked={form.enabled} onChange={(v) => set({ enabled: v })} disabled={ownerOnly} label="Enable single sign-on" hint="Shows your organization on the SSO sign-in page." />
          <Toggle
            checked={form.jitProvisioning}
            onChange={(v) => set({ jitProvisioning: v })}
            disabled={ownerOnly}
            label="Just-in-time provisioning"
            hint="People on a verified domain (or already invited) get an account on their first SSO sign-in. You still confirm them before they receive shared items."
          />
          <Toggle
            checked={form.enforce}
            onChange={(v) => set({ enforce: v })}
            disabled={ownerOnly}
            label="Require SSO for members"
            hint="Members can't sign in with e-mail and master password. Owners and admins keep it as a break-glass path."
          />
          <Toggle
            checked={form.groupSync}
            onChange={(v) => set({ groupSync: v })}
            disabled={ownerOnly}
            label="Sync group membership at sign-in"
            hint="Groups with an identity-provider ID (see Groups) follow the groups claim/attribute. Other groups are untouched."
          />
        </div>
        {!ownerOnly && (
          <div className="mt-5 flex justify-end">
            <button className="btn-primary" disabled={busy === 'save'} onClick={() => run('save', () => saveSso(orgId, toUpdate(form)), 'Single sign-on saved')}>
              {busy === 'save' && <Spinner />} Save
            </button>
          </div>
        )}
      </Section>

      <Section title="Verified domains" description="Proving you own a domain routes its users to your SSO and allows just-in-time accounts for it. Existing accounts on a verified domain are linked automatically.">
        <ul className="divide-y divide-slate-100 dark:divide-slate-800">
          {view.domains.map((d) => (
            <li key={d.id} className="py-3">
              <div className="flex items-center gap-3">
                <Globe className="h-5 w-5 text-slate-400" />
                <span className="flex-1 text-sm font-medium">{d.domain}</span>
                {d.verified ? <Badge tone="green">Verified</Badge> : <Badge tone="amber">Pending</Badge>}
                {!d.verified && isOwner && (
                  <button
                    className="btn-secondary text-xs"
                    disabled={busy === d.id}
                    onClick={() =>
                      run(d.id, async () => {
                        const res = await verifyDomain(orgId, d.id);
                        toast(res.verified ? `${d.domain} verified` : 'TXT record not found yet. DNS changes can take a while.', res.verified ? 'success' : 'error');
                      })
                    }
                  >
                    {busy === d.id ? <Spinner /> : <RefreshCw className="h-3.5 w-3.5" />} Verify
                  </button>
                )}
                {isOwner && (
                  <button className="icon-btn" title="Remove" onClick={() => run(d.id, () => removeDomain(orgId, d.id), 'Domain removed')}>
                    <Trash2 className="h-4 w-4" />
                  </button>
                )}
              </div>
              {!d.verified && (
                <div className="mt-3 grid gap-2 pl-8 sm:grid-cols-2">
                  <CopyField label="TXT record name" value={d.record.name} />
                  <CopyField label="TXT record value" value={d.record.value} />
                </div>
              )}
            </li>
          ))}
        </ul>
        {isOwner && (
          <form
            className="mt-3 flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              void run('domain', () => addDomain(orgId, newDomain.trim()).then(() => setNewDomain('')), 'Domain added. Publish the TXT record, then verify.');
            }}
          >
            <input className="input" placeholder="example.com" value={newDomain} onChange={(e) => setNewDomain(e.target.value)} />
            <button className="btn-secondary whitespace-nowrap" disabled={!newDomain || busy === 'domain'}>
              <Plus className="h-4 w-4" /> Add domain
            </button>
          </form>
        )}
      </Section>

      <Section
        title="SCIM provisioning"
        description="Your identity provider creates, updates and removes members and groups automatically. Deactivated users lose access immediately. New users are invited by e-mail, and you still confirm them before they receive the organization key."
        action={
          isOwner ? (
            <button className="btn-secondary text-xs" disabled={busy === 'token'} onClick={() => run('token', async () => setNewToken(await createScimToken(orgId, `Token ${tokens.length + 1}`)))}>
              <KeyRound className="h-3.5 w-3.5" /> New token
            </button>
          ) : undefined
        }
      >
        <CopyField label="SCIM base URL" value={view.scimBaseUrl} />
        <ul className="mt-3 divide-y divide-slate-100 dark:divide-slate-800">
          {tokens.map((t) => (
            <li key={t.id} className="flex items-center gap-3 py-2.5 text-sm">
              <KeyRound className="h-4 w-4 text-slate-400" />
              <span className="flex-1">{t.name}</span>
              <span className="text-xs text-slate-500">{t.lastUsedAt ? `used ${new Date(t.lastUsedAt).toLocaleString()}` : 'never used'}</span>
              {isOwner && (
                <button className="icon-btn" title="Revoke" onClick={() => run(t.id, () => revokeScimToken(orgId, t.id), 'Token revoked')}>
                  <Trash2 className="h-4 w-4" />
                </button>
              )}
            </li>
          ))}
          {tokens.length === 0 && <li className="py-2.5 text-sm text-slate-500">No tokens yet.</li>}
        </ul>
      </Section>

      {newToken && (
        <Modal title="SCIM token created" onClose={() => setNewToken(null)} footer={<button className="btn-primary" onClick={() => setNewToken(null)}>Done</button>}>
          <p className="text-sm text-slate-600 dark:text-slate-300">Paste this into your identity provider as the bearer token. It's shown only once.</p>
          <div className="mt-3"><CopyField label="Token" value={newToken.token ?? ''} /></div>
        </Modal>
      )}

      {reviewing && (
        <Modal
          title="Approve this device?"
          onClose={() => setReviewing(null)}
          footer={
            <>
              <button
                className="btn-secondary"
                disabled={!!busy}
                onClick={() => run('review', () => denyDeviceRequest(orgId, reviewing.id), 'Request denied').then(() => setReviewing(null))}
              >
                <X className="h-4 w-4" /> Deny
              </button>
              <button
                className="btn-primary"
                disabled={!!busy}
                onClick={() => run('review', () => approveDeviceRequest(orgId, reviewing), 'Device approved').then(() => setReviewing(null))}
              >
                {busy === 'review' ? <Spinner /> : <Check className="h-4 w-4" />} Approve
              </button>
            </>
          }
        >
          <p className="text-sm text-slate-600 dark:text-slate-300">
            <strong>{reviewing.email}</strong> asked to unlock <strong>{reviewing.deviceName}</strong>. Contact them through a channel you trust
            and make sure their screen shows this phrase:
          </p>
          <p className="mt-3 rounded-lg bg-slate-100 px-3 py-2 text-center font-mono text-sm dark:bg-slate-800">{fingerprint(fromB64(reviewing.publicKey))}</p>
          <p className="mt-3 text-xs text-slate-500">
            Approving uses the account-recovery key to give that device the member's vault key. The member is notified by e-mail, and the
            approval is audited.
          </p>
        </Modal>
      )}
    </div>
  );
}
