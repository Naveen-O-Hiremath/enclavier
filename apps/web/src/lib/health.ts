import { sha1 } from '@noble/hashes/legacy';
import { utf8 } from '@enclavier/crypto';
import type { BreachedAccount } from '@enclavier/shared';
import { api, apiText } from './api';
import type { VaultItem } from './session';
import { checkStrength } from './strength';

// Everything here runs in the browser on decrypted data: the server never
// learns which passwords are weak, reused or exposed.

export type IssueKind = 'exposed' | 'reused' | 'weak' | 'old' | 'insecure';

export interface HealthIssue {
  kind: IssueKind;
  detail: string;
}

export interface ItemHealth {
  item: VaultItem;
  issues: HealthIssue[];
}

export interface HealthReport {
  total: number;
  healthy: number;
  counts: Record<IssueKind, number>;
  items: ItemHealth[];
  breachCheck: 'done' | 'disabled' | 'failed';
  generatedAt: string;
}

const OLD_DAYS = 365;

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('').toUpperCase();

const rangeCache = new Map<string, Promise<Map<string, number>>>();

function fetchRange(prefix: string): Promise<Map<string, number>> {
  let p = rangeCache.get(prefix);
  if (!p) {
    p = apiText(`/api/breach/range/${prefix}`).then((text) => {
      const m = new Map<string, number>();
      for (const line of text.split('\n')) {
        const [suffix, count] = line.trim().split(':');
        // Padding entries (added by HIBP to hide response sizes) have count 0.
        if (suffix && Number(count) > 0) m.set(suffix.toUpperCase(), Number(count));
      }
      return m;
    });
    p.catch(() => rangeCache.delete(prefix));
    rangeCache.set(prefix, p);
  }
  return p;
}

/**
 * Pwned Passwords k-anonymity check: only the first 5 hex chars of the SHA-1
 * leave the browser; the suffix is matched locally. Returns the breach count.
 */
export async function timesExposed(password: string): Promise<number> {
  const h = hex(sha1(utf8.encode(password)));
  return (await fetchRange(h.slice(0, 5))).get(h.slice(5)) ?? 0;
}

export const breachStatus = () => api<{ passwords: boolean; accounts: boolean }>('GET', '/api/breach/status');
export const myBreachedAccounts = () => api<BreachedAccount[]>('GET', '/api/breach/account');

async function pool<T>(items: T[], limit: number, fn: (t: T) => Promise<void>) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) await fn(items[i++]!);
  }));
}

export async function analyzeVault(
  items: VaultItem[],
  opts: { checkBreaches: boolean; onProgress?: (done: number, total: number) => void },
): Promise<HealthReport> {
  const logins = items.filter((i) => !i.deletedAt && i.data.type === 'login' && i.data.login?.password);
  const byItem = new Map<string, HealthIssue[]>(logins.map((i) => [i.id, []]));
  const push = (id: string, issue: HealthIssue) => byItem.get(id)!.push(issue);

  // Reuse: same password in more than one item.
  const groups = new Map<string, VaultItem[]>();
  for (const i of logins) {
    const pw = i.data.login!.password!;
    groups.set(pw, [...(groups.get(pw) ?? []), i]);
  }
  for (const group of groups.values()) {
    if (group.length < 2) continue;
    for (const i of group) push(i.id, { kind: 'reused', detail: `Same password as ${group.length - 1} other item(s): ${group.filter((g) => g !== i).map((g) => g.data.name).slice(0, 3).join(', ')}` });
  }

  // Age and insecure URLs.
  const now = Date.now();
  for (const i of logins) {
    const changed = i.data.passwordHistory?.[0]?.changedAt ?? i.createdAt;
    const days = Math.floor((now - Date.parse(changed)) / 86_400_000);
    if (days > OLD_DAYS) push(i.id, { kind: 'old', detail: `Password unchanged for ${Math.floor(days / 30)} months` });
    const http = (i.data.login?.uris ?? []).filter((u) => /^http:\/\//i.test(u.trim()));
    if (http.length) push(i.id, { kind: 'insecure', detail: `Unencrypted website address: ${http[0]}` });
  }

  // Strength (zxcvbn, with the item's own name/username as context) and breaches.
  let done = 0;
  let breachCheck: HealthReport['breachCheck'] = opts.checkBreaches ? 'done' : 'disabled';
  const unique = [...groups.entries()];
  await pool(unique, 6, async ([password, group]) => {
    const context = group.flatMap((g) => [g.data.name, g.data.login?.username ?? '']);
    const { score } = await checkStrength(password, context);
    if (score <= 2) for (const i of group) push(i.id, { kind: 'weak', detail: `Strength ${score}/4: easy to guess` });
    if (opts.checkBreaches && breachCheck === 'done') {
      try {
        const n = await timesExposed(password);
        if (n > 0) for (const i of group) push(i.id, { kind: 'exposed', detail: `Seen ${n.toLocaleString()} times in data breaches` });
      } catch {
        breachCheck = 'failed';
      }
    }
    done += group.length;
    opts.onProgress?.(done, logins.length);
  });

  const order: IssueKind[] = ['exposed', 'reused', 'weak', 'old', 'insecure'];
  const counts = Object.fromEntries(order.map((k) => [k, 0])) as Record<IssueKind, number>;
  const withIssues: ItemHealth[] = [];
  for (const i of logins) {
    const issues = byItem.get(i.id)!.sort((a, b) => order.indexOf(a.kind) - order.indexOf(b.kind));
    for (const k of new Set(issues.map((x) => x.kind))) counts[k]++;
    if (issues.length) withIssues.push({ item: i, issues });
  }
  withIssues.sort((a, b) => order.indexOf(a.issues[0]!.kind) - order.indexOf(b.issues[0]!.kind) || a.item.data.name.localeCompare(b.item.data.name));

  return {
    total: logins.length,
    healthy: logins.length - withIssues.length,
    counts,
    items: withIssues,
    breachCheck,
    generatedAt: new Date().toISOString(),
  };
}
