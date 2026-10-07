import type { ZxcvbnFactory } from '@zxcvbn-ts/core';

// zxcvbn-ts with its dictionaries is ~1.5 MB, so it is loaded on first use.
let factory: Promise<ZxcvbnFactory> | null = null;

function load(): Promise<ZxcvbnFactory> {
  factory ??= (async () => {
    const [{ ZxcvbnFactory: Factory }, common, en] = await Promise.all([
      import('@zxcvbn-ts/core'),
      import('@zxcvbn-ts/language-common'),
      import('@zxcvbn-ts/language-en'),
    ]);
    return new Factory({
      translations: en.translations,
      graphs: common.adjacencyGraphs,
      dictionary: { ...common.dictionary, ...en.dictionary },
    });
  })();
  return factory;
}

export interface StrengthResult {
  /** 0 (trivially guessable) … 4 (very unguessable) */
  score: 0 | 1 | 2 | 3 | 4;
  warning: string | null;
  suggestions: string[];
}

/** Dictionary-, pattern- and keyboard-aware strength estimate (zxcvbn). */
export async function checkStrength(password: string, userInputs: string[] = []): Promise<StrengthResult> {
  const z = await load();
  const r = z.check(password.slice(0, 256), userInputs);
  return { score: r.score as StrengthResult['score'], warning: r.feedback.warning || null, suggestions: r.feedback.suggestions };
}

export const SCORE_LABELS = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'] as const;
