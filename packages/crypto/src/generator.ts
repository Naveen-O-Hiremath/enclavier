import { randomInt, shuffle } from './random';

export interface PasswordOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  /** Excludes look-alike characters such as 0/O and 1/l/I. */
  avoidAmbiguous: boolean;
}

export const DEFAULT_PASSWORD_OPTIONS: PasswordOptions = {
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  avoidAmbiguous: false,
};

const SETS = {
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?/~',
} as const;
const AMBIGUOUS = /[0O1lI|`'"]/g;

/** Generates a password with at least one character from each enabled set, unbiased. */
export function generatePassword(opts: PasswordOptions = DEFAULT_PASSWORD_OPTIONS): string {
  const sets = (Object.keys(SETS) as (keyof typeof SETS)[])
    .filter((k) => opts[k])
    .map((k) => (opts.avoidAmbiguous ? SETS[k].replace(AMBIGUOUS, '') : SETS[k]));
  if (sets.length === 0) throw new Error('Select at least one character set');
  const length = Math.max(opts.length, sets.length, 4);
  if (length > 256) throw new Error('Password too long');
  const all = sets.join('');
  const chars = sets.map((s) => s[randomInt(s.length)]!);
  while (chars.length < length) chars.push(all[randomInt(all.length)]!);
  return shuffle(chars).join('');
}

export function generatePin(length = 6): string {
  return Array.from({ length }, () => String(randomInt(10))).join('');
}

export type Strength = 0 | 1 | 2 | 3 | 4;

/**
 * Conservative strength estimate in bits. Penalises repeats and sequences; a full
 * dictionary-based estimator (zxcvbn) is added with the Phase 4 policy engine.
 */
export function estimateEntropy(password: string): number {
  if (!password) return 0;
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(password)) pool += 33;
  let effective = 0;
  for (let i = 0; i < password.length; i++) {
    const c = password.charCodeAt(i);
    const prev = password.charCodeAt(i - 1);
    const repeat = i > 0 && c === prev;
    const sequence = i > 0 && Math.abs(c - prev) === 1;
    effective += repeat || sequence ? 0.25 : 1;
  }
  return Math.round(effective * Math.log2(Math.max(pool, 1)));
}

export function strengthScore(password: string): Strength {
  const bits = estimateEntropy(password);
  if (bits < 28) return 0;
  if (bits < 40) return 1;
  if (bits < 60) return 2;
  if (bits < 80) return 3;
  return 4;
}
