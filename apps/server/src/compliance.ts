import type { ComplianceControl, ComplianceReport, ControlStatus, Framework, OrgPolicies } from '@enclavier/shared';
import { verifyOrgChain } from './audit';
import type { Queryable } from './db';

type Ref = ComplianceControl['references'][number];
const ref = (framework: Framework, control: string): Ref => ({ framework, control });

const INACTIVE_DAYS = 90;

const pct = (n: number, d: number) => (d === 0 ? 100 : Math.round((n / d) * 100));

/**
 * Evaluates an organization's live configuration against controls commonly
 * required by SOC 2, ISO/IEC 27001:2022, HIPAA, PCI DSS v4.0 and NIST SP 800-63B.
 * Everything here is derived from server-side facts; vault contents are never inspected.
 */
export async function buildComplianceReport(
  client: Queryable,
  input: { orgId: string; userId: string; policies: OrgPolicies; publicUrl: string },
): Promise<ComplianceReport> {
  const { orgId, policies } = input;

  const org = (await client.query<{ name: string; break_glass_created_at: Date | null }>(
    'SELECT name, break_glass_created_at FROM organizations WHERE id = $1',
    [orgId],
  )).rows[0]!;
  const actor = (await client.query<{ email: string }>('SELECT email FROM users WHERE id = $1', [input.userId])).rows[0]!;

  const members = (
    await client.query<{
      id: string; email: string; role: string; status: string; revoked: boolean; invite_expired: boolean;
      totp: boolean; webauthn: boolean; last_active: Date | null;
    }>(
      `SELECT m.id, m.email, m.role, m.status, m.revoked_at IS NOT NULL AS revoked,
              (m.status = 'invited' AND m.invite_expires_at < now()) AS invite_expired,
              u.totp_enabled_at IS NOT NULL AS totp,
              EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id = u.id) AS webauthn,
              (SELECT max(s.last_used_at) FROM sessions s WHERE s.user_id = u.id) AS last_active
         FROM org_members m LEFT JOIN users u ON u.id = m.user_id
        WHERE m.org_id = $1`,
      [orgId],
    )
  ).rows;
  const active = members.filter((m) => m.status === 'confirmed' && !m.revoked);
  const withMfa = active.filter((m) => m.totp || m.webauthn);
  const phishingResistant = active.filter((m) => m.webauthn);
  const admins = active.filter((m) => m.role === 'owner' || m.role === 'admin');
  const owners = active.filter((m) => m.role === 'owner');
  const cutoff = Date.now() - INACTIVE_DAYS * 86_400_000;
  const inactive = active.filter((m) => !m.last_active || m.last_active.getTime() < cutoff);
  const expiredInvites = members.filter((m) => m.invite_expired);
  const revoked = members.filter((m) => m.revoked);
  const pendingConfirm = members.filter((m) => m.status === 'accepted' && !m.revoked);

  const destinations = (
    await client.query<{ enabled: boolean; failures: number; last_success_at: Date | null }>(
      'SELECT enabled, failures, last_success_at FROM log_destinations WHERE org_id = $1',
      [orgId],
    )
  ).rows.filter((d) => d.enabled);
  const healthyDest = destinations.filter((d) => d.failures === 0 && d.last_success_at);

  const chain = await verifyOrgChain(client, orgId);
  const list = (xs: { email: string }[], max = 5) => xs.slice(0, max).map((x) => x.email).join(', ') + (xs.length > max ? `, +${xs.length - max} more` : '');

  const controls: ComplianceControl[] = [];
  const add = (c: Omit<ComplianceControl, 'recommendation'> & { recommendation?: string | null }) =>
    controls.push({ ...c, recommendation: c.status === 'pass' ? null : (c.recommendation ?? null) });

  const MFA_REFS = [
    ref('SOC 2', 'CC6.1'),
    ref('ISO 27001', 'A.8.5 Secure authentication'),
    ref('HIPAA', '§164.312(d) Person or entity authentication'),
    ref('PCI DSS', '8.4.2 MFA for all access into the CDE'),
    ref('NIST 800-63B', '§4.2 AAL2'),
  ];

  add({
    id: 'mfa-enforced',
    title: 'Multi-factor authentication is enforced',
    status: policies.require2fa ? 'pass' : 'fail',
    evidence: policies.require2fa ? 'The "Require two-step login" policy is enabled.' : 'Two-step login is optional for members.',
    recommendation: 'Enable Policies → Require two-step login.',
    references: MFA_REFS,
  });

  const mfaPct = pct(withMfa.length, active.length);
  add({
    id: 'mfa-coverage',
    title: 'Members have a second factor enrolled',
    status: mfaPct === 100 ? 'pass' : mfaPct >= 80 ? 'warn' : 'fail',
    evidence: `${withMfa.length} of ${active.length} active members (${mfaPct}%) have TOTP or a security key.`,
    recommendation: `Follow up with: ${list(active.filter((m) => !m.totp && !m.webauthn))}.`,
    references: MFA_REFS,
  });

  const prPct = pct(phishingResistant.length, active.length);
  add({
    id: 'phishing-resistant-mfa',
    title: 'Phishing-resistant authenticators (FIDO2/WebAuthn)',
    status: prPct === 100 ? 'pass' : phishingResistant.length > 0 ? 'warn' : 'info',
    evidence: `${phishingResistant.length} of ${active.length} active members (${prPct}%) use a security key or passkey.`,
    recommendation: 'Issue FIDO2 security keys or passkeys, starting with owners and admins.',
    references: [ref('NIST 800-63B', '§4.3 AAL3 / §5.2.5 verifier impersonation resistance'), ref('SOC 2', 'CC6.1'), ref('PCI DSS', '8.4 / 8.5 MFA systems')],
  });

  const mp = policies.masterPassword;
  add({
    id: 'password-policy',
    title: 'Master password strength requirements',
    status: !mp ? 'fail' : mp.minLength >= 12 && mp.minScore >= 3 ? 'pass' : 'warn',
    evidence: mp ? `Minimum length ${mp.minLength}, minimum strength score ${mp.minScore}/4 (checked against common-password dictionaries on each unlock).` : 'No master password policy is set.',
    recommendation: 'Set Policies → Master password to at least 12 characters (14+ recommended) and strength 3 or higher.',
    references: [
      ref('PCI DSS', '8.3.6 Minimum 12 characters'),
      ref('NIST 800-63B', '§5.1.1.2 Memorized secret verifiers (blocklist)'),
      ref('ISO 27001', 'A.5.17 Authentication information'),
      ref('HIPAA', '§164.308(a)(5)(ii)(D) Password management'),
    ],
  });

  const vt = policies.vaultTimeout;
  add({
    id: 'session-timeout',
    title: 'Automatic lock after inactivity',
    status: !vt ? 'fail' : vt.maxMinutes <= 15 ? 'pass' : vt.maxMinutes <= 30 ? 'warn' : 'fail',
    evidence: vt ? `Vaults lock after at most ${vt.maxMinutes} minute(s) of inactivity.` : 'Members choose their own auto-lock timeout (including "never").',
    recommendation: 'Set Policies → Vault timeout to 15 minutes or less.',
    references: [
      ref('PCI DSS', '8.2.8 Re-authenticate after 15 minutes idle'),
      ref('HIPAA', '§164.312(a)(2)(iii) Automatic logoff'),
      ref('ISO 27001', 'A.8.1 User endpoint devices'),
      ref('SOC 2', 'CC6.1'),
    ],
  });

  const cb = policies.clipboard;
  add({
    id: 'clipboard',
    title: 'Copied secrets are cleared from the clipboard',
    status: cb && cb.maxSeconds <= 60 ? 'pass' : 'warn',
    evidence: cb ? `Clipboard is cleared within ${cb.maxSeconds} seconds.` : 'Members can disable clipboard clearing.',
    recommendation: 'Set Policies → Clipboard to 60 seconds or less.',
    references: [ref('ISO 27001', 'A.8.12 Data leakage prevention'), ref('SOC 2', 'CC6.7')],
  });

  add({
    id: 'audit-integrity',
    title: 'Tamper-evident audit trail is intact',
    status: chain.ok ? 'pass' : 'fail',
    evidence: chain.ok
      ? `${chain.checked} events verified in the organization hash chain${chain.head ? ` (head #${chain.head.seq} ${chain.head.hash.slice(0, 16)}…)` : ''}${chain.legacy ? `; ${chain.legacy} earlier events are covered by the global chain` : ''}.`
      : `Chain broken at event #${chain.brokenAtSeq}: ${chain.reason}.`,
    recommendation: 'Investigate immediately: audit events were altered or deleted at the database level.',
    references: [ref('SOC 2', 'CC7.2'), ref('ISO 27001', 'A.8.15 Logging'), ref('HIPAA', '§164.312(b) Audit controls'), ref('PCI DSS', '10.3.2 / 10.3.4 Protect audit logs')],
  });

  add({
    id: 'log-streaming',
    title: 'Audit events are forwarded to a SIEM',
    status: healthyDest.length > 0 && healthyDest.length === destinations.length ? 'pass' : destinations.length > 0 ? 'fail' : 'warn',
    evidence:
      destinations.length === 0
        ? 'No log destination is configured.'
        : `${healthyDest.length} of ${destinations.length} enabled destination(s) delivering successfully.`,
    recommendation: destinations.length === 0 ? 'Add a destination under Log streaming (Splunk, Sentinel, Datadog, syslog…).' : 'Fix failing destinations under Log streaming.',
    references: [ref('SOC 2', 'CC7.2 / CC7.3'), ref('ISO 27001', 'A.8.16 Monitoring activities'), ref('PCI DSS', '10.4.1 Daily log review'), ref('HIPAA', '§164.308(a)(1)(ii)(D) Activity review')],
  });

  const hygieneIssues = [
    inactive.length && `${inactive.length} member(s) inactive for ${INACTIVE_DAYS}+ days (${list(inactive)})`,
    expiredInvites.length && `${expiredInvites.length} expired invitation(s)`,
    revoked.length && `${revoked.length} revoked member(s) not yet removed`,
    pendingConfirm.length && `${pendingConfirm.length} member(s) awaiting confirmation`,
  ].filter(Boolean) as string[];
  add({
    id: 'access-review',
    title: 'Stale and unused access is removed',
    status: inactive.length ? 'warn' : hygieneIssues.length ? 'warn' : 'pass',
    evidence: hygieneIssues.length ? `${hygieneIssues.join('; ')}.` : 'No inactive accounts, expired invitations or lingering revoked members.',
    recommendation: 'Review members: remove inactive accounts and expired invitations.',
    references: [ref('SOC 2', 'CC6.2 / CC6.3'), ref('ISO 27001', 'A.5.18 Access rights'), ref('PCI DSS', '8.2.6 Inactive accounts removed within 90 days'), ref('HIPAA', '§164.308(a)(4) Access management')],
  });

  const adminLimit = Math.max(3, Math.ceil(active.length * 0.2));
  add({
    id: 'least-privilege',
    title: 'Administrative access is limited',
    status: admins.length <= adminLimit ? 'pass' : 'warn',
    evidence: `${owners.length} owner(s) and ${admins.length - owners.length} admin(s) among ${active.length} active members.`,
    recommendation: `Reduce owners/admins to ${adminLimit} or fewer; use collection "manage" permissions for delegated administration.`,
    references: [ref('PCI DSS', '7.2.2 Least privilege'), ref('SOC 2', 'CC6.3'), ref('ISO 27001', 'A.8.2 Privileged access rights')],
  });

  const continuity = owners.length >= 2 || !!org.break_glass_created_at;
  add({
    id: 'continuity',
    title: 'Organization access survives the loss of an owner',
    status: continuity ? 'pass' : 'warn',
    evidence: `${owners.length} owner(s); break-glass recovery kit ${org.break_glass_created_at ? `created ${org.break_glass_created_at.toISOString().slice(0, 10)}` : 'not created'}.`,
    recommendation: 'Add a second owner or create a break-glass recovery kit (Settings).',
    references: [ref('ISO 27001', 'A.5.29 / A.5.30 ICT continuity'), ref('SOC 2', 'A1.2 / CC9.1'), ref('HIPAA', '§164.308(a)(7) Contingency plan')],
  });

  add({
    id: 'export-control',
    title: 'Plaintext vault export is restricted',
    status: policies.disableExport ? 'pass' : 'info',
    evidence: policies.disableExport ? 'Members cannot export their vault.' : 'Members may export their personal vault (organization items are never exported).',
    recommendation: 'Enable Policies → Disable export if exports are not permitted.',
    references: [ref('ISO 27001', 'A.8.12 Data leakage prevention'), ref('SOC 2', 'CC6.7')],
  });

  const https = input.publicUrl.startsWith('https://');
  add({
    id: 'encryption',
    title: 'Secrets are encrypted at rest and in transit',
    status: https ? 'pass' : 'warn',
    evidence: `End-to-end encryption (XChaCha20-Poly1305, Argon2id key derivation): the server stores ciphertext only. Web vault served over ${https ? 'HTTPS' : 'plain HTTP (PUBLIC_URL)'}.`,
    recommendation: 'Serve the vault over HTTPS (TLS 1.2+) and set PUBLIC_URL accordingly.',
    references: [
      ref('SOC 2', 'CC6.1 / CC6.7'),
      ref('ISO 27001', 'A.8.24 Use of cryptography'),
      ref('HIPAA', '§164.312(a)(2)(iv) / (e)(1) Encryption'),
      ref('PCI DSS', '3.5.1 / 4.2.1 Strong cryptography'),
    ],
  });

  add({
    id: 'account-recovery',
    title: 'Master password recovery process',
    status: 'info',
    evidence: policies.accountRecovery
      ? 'Account recovery is enabled: administrators can reset enrolled members’ master passwords (each reset is audited and e-mailed).'
      : 'Account recovery is disabled: a forgotten master password cannot be reset.',
    recommendation: 'Document the chosen trade-off between recoverability and admin access in your access-control policy.',
    references: [ref('ISO 27001', 'A.5.17 Authentication information'), ref('SOC 2', 'CC6.2')],
  });

  const gen = policies.passwordGenerator;
  add({
    id: 'generator-policy',
    title: 'Generated credentials meet a minimum strength',
    status: gen && gen.minLength >= 14 ? 'pass' : 'info',
    evidence: gen ? `Generator minimum length ${gen.minLength}.` : 'Members choose generator settings freely.',
    recommendation: 'Set Policies → Password generator to 14+ characters.',
    references: [ref('NIST 800-63B', '§5.1.1 Memorized secrets'), ref('ISO 27001', 'A.5.17 Authentication information')],
  });

  const summary: Record<ControlStatus, number> = { pass: 0, warn: 0, fail: 0, info: 0 };
  for (const c of controls) summary[c.status]++;
  const frameworks = (['SOC 2', 'ISO 27001', 'HIPAA', 'PCI DSS', 'NIST 800-63B'] as Framework[]).map((framework) => {
    const relevant = controls.filter((c) => c.status !== 'info' && c.references.some((r) => r.framework === framework));
    return { framework, pass: relevant.filter((c) => c.status === 'pass').length, total: relevant.length };
  });

  return {
    organization: { id: orgId, name: org.name },
    generatedAt: new Date().toISOString(),
    generatedBy: actor.email,
    summary,
    frameworks,
    controls,
    auditChainHead: chain.ok ? chain.head : null,
    disclaimer:
      'This posture report evaluates Enclavier configuration against controls commonly required by these frameworks. It is a readiness aid and evidence source, not a certification or audit opinion; controls outside Enclavier are not assessed.',
  };
}
