import { z } from 'zod';

const bool = z
  .enum(['true', 'false', '1', '0'])
  .transform((v) => v === 'true' || v === '1');

const schema = z.object({
  DATABASE_URL: z.string().url(),
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
  SERVER_SECRET: z.string().min(32, 'SERVER_SECRET must be at least 32 characters'),
  HOST: z.string().default('0.0.0.0'),
  PORT: z.coerce.number().int().default(8080),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  SIGNUPS_ENABLED: bool.default('true'),
  TRUST_PROXY: bool.default('false'),
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).default(900),
  REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().min(1).default(30),
  /** Public URL of the web vault; used in e-mail links. */
  PUBLIC_URL: z.string().url().default('http://localhost:5173'),
  /** WebAuthn relying party; defaults to the PUBLIC_URL hostname. Must match the domain users visit. */
  WEBAUTHN_RP_ID: z.string().optional(),
  WEBAUTHN_RP_NAME: z.string().default('Enclavier'),
  /** Allow SIEM destinations on private networks (self-hosted internal SIEMs). Keep false for SaaS. */
  ALLOW_PRIVATE_LOG_DESTINATIONS: bool.default('false'),
  LOG_STREAM_INTERVAL_MS: z.coerce.number().int().min(500).default(5000),
  /** Allow OIDC identity providers on private networks (self-hosted Keycloak, ADFS…). Keep false for SaaS. */
  ALLOW_PRIVATE_SSO_ENDPOINTS: bool.default('false'),
  /** Pwned Passwords range API (or an offline mirror). Empty disables breach checks. */
  HIBP_API_URL: z.string().default('https://api.pwnedpasswords.com'),
  /** Optional HIBP API key enabling breached-account (e-mail) checks. */
  HIBP_API_KEY: z.string().optional(),
  INVITE_TTL_DAYS: z.coerce.number().int().min(1).max(30).default(7),
  /** SMTP is optional: without SMTP_HOST, e-mails are written to the server log. */
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.coerce.number().int().default(587),
  SMTP_SECURE: bool.default('false'),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),
  SMTP_FROM: z.string().default('Enclavier <no-reply@enclavier.local>'),
});

export type Config = z.infer<typeof schema>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `  ${i.path.join('.')}: ${i.message}`).join('\n');
    throw new Error(`Invalid configuration:\n${issues}`);
  }
  return parsed.data;
}
