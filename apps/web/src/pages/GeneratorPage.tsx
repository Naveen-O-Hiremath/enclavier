import { useCallback, useEffect, useState } from 'react';
import { Copy, RefreshCw } from 'lucide-react';
import { DEFAULT_PASSWORD_OPTIONS, estimateEntropy, generatePassword, type PasswordOptions } from '@enclavier/crypto';
import { copyWithToast, StrengthMeter } from '../components/ui';
import { applyGeneratorPolicy, currentPolicy, useEffectivePolicy } from '../lib/policy';

const KEY = 'enclavier.generator';

export function loadGeneratorOptions(): PasswordOptions {
  let saved = DEFAULT_PASSWORD_OPTIONS;
  try {
    saved = { ...DEFAULT_PASSWORD_OPTIONS, ...(JSON.parse(localStorage.getItem(KEY) ?? '{}') as Partial<PasswordOptions>) };
  } catch {
    // fall back to defaults
  }
  return applyGeneratorPolicy(saved, currentPolicy());
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex cursor-pointer items-center justify-between py-2.5 text-sm">
      {label}
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className={`relative h-5 w-9 rounded-full transition ${checked ? 'bg-brand-600' : 'bg-slate-300 dark:bg-slate-700'}`}
      >
        <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white shadow transition ${checked ? 'left-4.5' : 'left-0.5'}`} />
      </button>
    </label>
  );
}

export function GeneratorPage() {
  const policy = useEffectivePolicy();
  const g = policy.generator;
  const [opts, setOpts] = useState<PasswordOptions>(loadGeneratorOptions);
  const [value, setValue] = useState('');

  const regenerate = useCallback(() => {
    try {
      setValue(generatePassword(opts));
    } catch {
      setValue('');
    }
  }, [opts]);

  useEffect(() => {
    localStorage.setItem(KEY, JSON.stringify(opts));
    regenerate();
  }, [opts, regenerate]);

  const set = (patch: Partial<PasswordOptions>) => {
    const next = applyGeneratorPolicy({ ...opts, ...patch }, policy);
    if (!next.lowercase && !next.uppercase && !next.digits && !next.symbols) return; // keep at least one set
    setOpts(next);
  };

  return (
    <div className="mx-auto max-w-xl p-6">
      <h1 className="mb-1 text-lg font-semibold">Password generator</h1>
      <p className="mb-6 text-sm text-slate-500">Generated locally with a cryptographically secure random source.</p>

      <div className="card p-5">
        <div className="flex items-center gap-2">
          <div className="min-w-0 flex-1 rounded-lg bg-slate-100 px-4 py-3 font-mono text-lg break-all dark:bg-slate-800">{value}</div>
          <button className="icon-btn h-10 w-10" onClick={regenerate} aria-label="Regenerate"><RefreshCw className="h-4 w-4" /></button>
          <button className="icon-btn h-10 w-10" onClick={() => copyWithToast(value, 'Password')} aria-label="Copy"><Copy className="h-4 w-4" /></button>
        </div>
        <StrengthMeter password={value} />
        <div className="mt-1 text-right text-xs text-slate-400">≈ {estimateEntropy(value)} bits of entropy</div>
      </div>

      {g && (
        <p className="mt-4 text-xs text-slate-500">
          Minimums set by {g.sources.join(', ')}: {g.minLength}+ characters
          {[g.requireUppercase && 'uppercase', g.requireLowercase && 'lowercase', g.requireDigits && 'numbers', g.requireSymbols && 'symbols'].filter(Boolean).map((x) => `, ${x}`).join('')}.
        </p>
      )}
      <div className="card mt-4 divide-y divide-slate-100 px-5 dark:divide-slate-800">
        <div className="py-3">
          <div className="flex items-center justify-between text-sm">
            <span>Length</span>
            <span className="font-mono font-medium">{opts.length}</span>
          </div>
          <input type="range" min={g?.minLength ?? 8} max={Math.max(64, g?.minLength ?? 0)} value={opts.length} onChange={(e) => set({ length: Number(e.target.value) })} className="mt-2 w-full accent-brand-600" />
        </div>
        <Toggle label="Uppercase (A-Z)" checked={opts.uppercase} onChange={(v) => set({ uppercase: v })} />
        <Toggle label="Lowercase (a-z)" checked={opts.lowercase} onChange={(v) => set({ lowercase: v })} />
        <Toggle label="Numbers (0-9)" checked={opts.digits} onChange={(v) => set({ digits: v })} />
        <Toggle label="Symbols (!@#$…)" checked={opts.symbols} onChange={(v) => set({ symbols: v })} />
        <Toggle label="Avoid ambiguous characters" checked={opts.avoidAmbiguous} onChange={(v) => set({ avoidAmbiguous: v })} />
      </div>
    </div>
  );
}
