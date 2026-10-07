import nodemailer from 'nodemailer';
import type { FastifyBaseLogger } from 'fastify';
import { BRAND_LOGO_PNG } from './brandLogo';
import type { Config } from './config';

export interface MailMessage {
  to: string;
  subject: string;
  text: string;
  html: string;
  /** Inline images referenced from the HTML as cid:<cid>. */
  attachments?: { filename: string; content: Buffer; cid: string; contentType: string }[];
}

export interface Mailer {
  send(message: MailMessage): Promise<void>;
}

/** SMTP when configured (SendGrid, SES, M365, Postfix…); otherwise logs mail for development/air-gapped setups. */
export function createMailer(config: Config, log: Pick<FastifyBaseLogger, 'warn' | 'info'>): Mailer {
  const missingPassword = !!config.SMTP_USER && !config.SMTP_PASS;
  if (!config.SMTP_HOST || missingPassword) {
    const reason = missingPassword ? 'SMTP_PASS is not set' : 'SMTP is not configured';
    return {
      async send(m) {
        log.warn({ to: m.to, subject: m.subject, body: m.text }, `${reason} — e-mail logged instead of sent`);
      },
    };
  }
  const transport = nodemailer.createTransport({
    host: config.SMTP_HOST,
    port: config.SMTP_PORT,
    secure: config.SMTP_SECURE,
    auth: config.SMTP_USER ? { user: config.SMTP_USER, pass: config.SMTP_PASS } : undefined,
  });
  return {
    async send(m) {
      const info = await transport.sendMail({ from: config.SMTP_FROM, ...m });
      // Delivery evidence for operators ("the invitation never arrived"): what the SMTP server accepted.
      if (info.rejected?.length) throw new Error(`SMTP server rejected ${info.rejected.join(', ')}: ${info.response}`);
      log.info({ to: m.to, subject: m.subject, messageId: info.messageId, response: info.response }, 'E-mail handed to SMTP server');
    },
  };
}

const escape = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

/** Header values must stay on one line (names come from users). */
const oneLine = (s: string) => s.replace(/[\r\n]+/g, ' ').trim();

export interface NoticeInput {
  subject: string;
  /** Large title inside the message; defaults to the subject. */
  heading?: string;
  /** Inbox preview line shown next to the subject by most mail clients. */
  preheader?: string;
  /** Paragraphs of plain text; `**bold**` spans are rendered bold in HTML. */
  paragraphs: string[];
  /** A highlighted card (who invited you, which device, …). */
  panel?: { title: string; subtitle?: string; initials?: string };
  cta?: { label: string; url: string };
  /** Short numbered steps shown under the button. */
  steps?: string[];
  footnote?: string;
  /** `security` marks account-security notices with an amber accent. */
  tone?: 'brand' | 'security';
}

const FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
const BRAND = '#4f46e5';

/**
 * One layout for every Enclavier e-mail (text + HTML). Table-based with inline
 * styles so it renders the same in Gmail, Outlook and Apple Mail; no remote
 * images, so nothing is blocked or tracked.
 */
export function noticeEmail(n: NoticeInput): Omit<MailMessage, 'to'> {
  const plain = (p: string) => p.replace(/\*\*(.+?)\*\*/g, '$1');
  const rich = (p: string) => escape(p).replace(/\*\*(.+?)\*\*/g, '<strong style="color:#0f172a">$1</strong>');
  const heading = n.heading ?? n.subject;
  const accent = n.tone === 'security' ? '#d97706' : BRAND;

  const text = [
    heading,
    ...n.paragraphs.map(plain),
    ...(n.panel ? [[n.panel.title, n.panel.subtitle].filter(Boolean).join(' — ')] : []),
    ...(n.cta ? [`${n.cta.label}: ${n.cta.url}`] : []),
    ...(n.steps?.length ? [n.steps.map((st, i) => `${i + 1}. ${plain(st)}`).join('\n')] : []),
    ...(n.footnote ? [plain(n.footnote)] : []),
    '--\nEnclavier · Zero-knowledge password manager\nThis is an automated message. Please do not reply.',
  ].join('\n\n');

  const panel = n.panel
    ? `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 24px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px">
        <tr>
          ${
            n.panel.initials
              ? `<td width="44" valign="middle" style="padding:16px 0 16px 16px"><div style="width:44px;height:44px;line-height:44px;border-radius:12px;background:#e0e7ff;color:#4338ca;font:700 16px ${FONT};line-height:44px;text-align:center">${escape(n.panel.initials)}</div></td>`
              : ''
          }
          <td valign="middle" style="padding:16px">
            <div style="font:600 16px/1.3 ${FONT};color:#0f172a">${escape(n.panel.title)}</div>
            ${n.panel.subtitle ? `<div style="font:400 13px/1.4 ${FONT};color:#64748b;margin-top:2px">${escape(n.panel.subtitle)}</div>` : ''}
          </td>
        </tr>
      </table>`
    : '';

  const button = n.cta
    ? `<table role="presentation" cellpadding="0" cellspacing="0" style="margin:4px 0 20px"><tr>
        <td align="center" bgcolor="${accent}" style="border-radius:10px">
          <a href="${escape(n.cta.url)}" target="_blank" style="display:inline-block;padding:14px 28px;font:600 15px ${FONT};color:#ffffff;text-decoration:none;border-radius:10px">${escape(n.cta.label)}</a>
        </td></tr></table>
      <p style="font:400 12px/1.5 ${FONT};color:#64748b;margin:0 0 4px">Button not working? Paste this link into your browser:</p>
      <p style="font:400 12px/1.5 ${FONT};margin:0 0 24px;word-break:break-all"><a href="${escape(n.cta.url)}" style="color:${accent};text-decoration:underline">${escape(n.cta.url)}</a></p>`
    : '';

  const steps = n.steps?.length
    ? `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 24px">${n.steps
        .map(
          (st, i) => `<tr>
            <td width="28" valign="top" style="padding:0 0 10px"><div style="width:22px;height:22px;border-radius:11px;background:#eef2ff;color:#4338ca;font:600 12px ${FONT};line-height:22px;text-align:center">${i + 1}</div></td>
            <td valign="top" style="padding:1px 0 10px;font:400 14px/1.5 ${FONT};color:#475569">${rich(st)}</td>
          </tr>`,
        )
        .join('')}</table>`
    : '';

  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light">
<meta name="supported-color-schemes" content="light">
<title>${escape(n.subject)}</title>
</head>
<body style="margin:0;padding:0;background:#f1f5f9;-webkit-text-size-adjust:100%">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent">${escape(plain(n.preheader ?? n.paragraphs[0] ?? ''))}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9">
  <tr><td align="center" style="padding:32px 16px">
    <table role="presentation" width="560" cellpadding="0" cellspacing="0" style="width:100%;max-width:560px">
      <tr><td style="padding:0 4px 20px">
        <table role="presentation" cellpadding="0" cellspacing="0"><tr>
          <td valign="middle"><img src="cid:enclavier-logo" width="40" height="40" alt="Enclavier" style="display:block;width:40px;height:40px;border:0;border-radius:9px"></td>
          <td valign="middle" style="padding-left:10px;font:600 19px ${FONT};color:#0f172a;letter-spacing:-0.2px">Enclavier</td>
        </tr></table>
      </td></tr>
      <tr><td style="background:#ffffff;border:1px solid #e2e8f0;border-radius:16px;overflow:hidden">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
          <tr><td style="height:4px;background:${accent};font-size:0;line-height:0">&nbsp;</td></tr>
          <tr><td style="padding:36px 36px 28px">
            <h1 style="font:700 22px/1.3 ${FONT};color:#0f172a;margin:0 0 16px;letter-spacing:-0.3px">${escape(heading)}</h1>
            ${n.paragraphs.map((p) => `<p style="font:400 15px/1.6 ${FONT};color:#475569;margin:0 0 20px">${rich(p)}</p>`).join('')}
            ${panel}
            ${button}
            ${steps}
            ${n.footnote ? `<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td style="border-top:1px solid #e2e8f0;padding-top:20px;font:400 13px/1.6 ${FONT};color:#64748b">${rich(n.footnote)}</td></tr></table>` : ''}
          </td></tr>
        </table>
      </td></tr>
      <tr><td align="center" style="padding:24px 16px 0;font:400 12px/1.6 ${FONT};color:#94a3b8">
        <strong style="color:#64748b">Enclavier</strong> · Zero-knowledge password manager<br>
        Your vault is encrypted on your devices. We can never see your master password or what you store.<br>
        This is an automated message. Please do not reply.
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`;
  const attachments = [{ filename: 'enclavier.png', content: BRAND_LOGO_PNG, cid: 'enclavier-logo', contentType: 'image/png' }];
  return { subject: oneLine(n.subject), text, html, attachments };
}

function initialsOf(name: string): string {
  const words = name.trim().split(/\s+/).filter(Boolean);
  return ((words[0]?.[0] ?? '') + (words.length > 1 ? words[words.length - 1]![0] : (words[0]?.[1] ?? ''))).toUpperCase();
}

export function inviteEmail(p: { orgName: string; inviterName: string; link: string; expiresDays: number; email?: string; role?: string }) {
  const role = p.role && p.role !== 'member' ? ` as an ${p.role}` : '';
  return noticeEmail({
    subject: `${p.inviterName} invited you to join ${p.orgName} on Enclavier`,
    heading: `Join ${p.orgName} on Enclavier`,
    preheader: `${p.inviterName} invited you${role}. Accept within ${p.expiresDays} days.`,
    paragraphs: [
      `**${p.inviterName}** has invited you to join **${p.orgName}**${role}. Enclavier is where the team keeps and shares passwords and other secrets securely.`,
    ],
    panel: { title: p.orgName, subtitle: `Invited by ${p.inviterName}${p.email ? ` · for ${p.email}` : ''}`, initials: initialsOf(p.orgName) },
    cta: { label: 'Accept invitation', url: p.link },
    steps: [
      'Accept the invitation and sign in, or create your account.',
      'Choose a strong master password. Only you know it.',
      'An administrator confirms you, and shared items appear in your vault.',
    ],
    footnote: `This invitation expires in **${p.expiresDays} days** and works only for this e-mail address. If you weren't expecting it, you can safely ignore this message.`,
  });
}
