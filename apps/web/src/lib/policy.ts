import type { GeneratorPolicy, MasterPasswordPolicy } from '@enclavier/shared';
import type { PasswordOptions } from '@enclavier/crypto';
import { useSession, type VaultOrg } from './session';
import { useSettings } from './settings';

/** The strictest combination of every policy from organizations the user belongs to. */
export interface EffectivePolicy {
  masterPassword: (MasterPasswordPolicy & { sources: string[] }) | null;
  generator: (GeneratorPolicy & { sources: string[] }) | null;
  maxAutoLockMinutes: { value: number; sources: string[] } | null;
  maxClipboardSeconds: { value: number; sources: string[] } | null;
  exportDisabledBy: string[];
}

export function effectivePolicy(orgs: VaultOrg[]): EffectivePolicy {
  const out: EffectivePolicy = { masterPassword: null, generator: null, maxAutoLockMinutes: null, maxClipboardSeconds: null, exportDisabledBy: [] };
  for (const o of orgs) {
    if (o.status !== 'confirmed') continue;
    const p = o.policies;
    if (p.masterPassword) {
      const cur = out.masterPassword;
      out.masterPassword = {
        minLength: Math.max(cur?.minLength ?? 0, p.masterPassword.minLength),
        minScore: Math.max(cur?.minScore ?? 0, p.masterPassword.minScore),
        sources: [...(cur?.sources ?? []), o.name],
      };
    }
    if (p.passwordGenerator) {
      const cur = out.generator;
      const g = p.passwordGenerator;
      out.generator = {
        minLength: Math.max(cur?.minLength ?? 0, g.minLength),
        requireUppercase: !!cur?.requireUppercase || g.requireUppercase,
        requireLowercase: !!cur?.requireLowercase || g.requireLowercase,
        requireDigits: !!cur?.requireDigits || g.requireDigits,
        requireSymbols: !!cur?.requireSymbols || g.requireSymbols,
        sources: [...(cur?.sources ?? []), o.name],
      };
    }
    if (p.vaultTimeout) {
      const cur = out.maxAutoLockMinutes;
      out.maxAutoLockMinutes = { value: Math.min(cur?.value ?? Infinity, p.vaultTimeout.maxMinutes), sources: [...(cur?.sources ?? []), o.name] };
    }
    if (p.clipboard) {
      const cur = out.maxClipboardSeconds;
      out.maxClipboardSeconds = { value: Math.min(cur?.value ?? Infinity, p.clipboard.maxSeconds), sources: [...(cur?.sources ?? []), o.name] };
    }
    if (p.disableExport) out.exportDisabledBy.push(o.name);
  }
  return out;
}

export function useEffectivePolicy(): EffectivePolicy {
  return effectivePolicy(useSession((s) => s.organizations));
}

/** Auto-lock minutes after policy (0 = never is not allowed when capped). */
export function effectiveAutoLock(userMinutes: number, policy: EffectivePolicy): number {
  const cap = policy.maxAutoLockMinutes?.value;
  if (!cap) return userMinutes;
  return userMinutes === 0 ? cap : Math.min(userMinutes, cap);
}

export function effectiveClipboardSeconds(userSeconds: number, policy: EffectivePolicy): number {
  const cap = policy.maxClipboardSeconds?.value;
  if (!cap) return userSeconds;
  return userSeconds === 0 ? cap : Math.min(userSeconds, cap);
}

/** Raises generator options to the org minimums. */
export function applyGeneratorPolicy(opts: PasswordOptions, policy: EffectivePolicy): PasswordOptions {
  const g = policy.generator;
  if (!g) return opts;
  return {
    ...opts,
    length: Math.max(opts.length, g.minLength),
    uppercase: opts.uppercase || g.requireUppercase,
    lowercase: opts.lowercase || g.requireLowercase,
    digits: opts.digits || g.requireDigits,
    symbols: opts.symbols || g.requireSymbols,
  };
}

/** Current values for non-React callers (clipboard, auto-lock timer). */
export function currentPolicy(): EffectivePolicy {
  return effectivePolicy(useSession.getState().organizations);
}

export function currentClipboardSeconds(): number {
  return effectiveClipboardSeconds(useSettings.getState().clipboardClearSeconds, currentPolicy());
}
