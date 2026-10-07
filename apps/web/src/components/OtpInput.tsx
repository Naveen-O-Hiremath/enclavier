import { useEffect, useRef, type ClipboardEvent, type KeyboardEvent } from 'react';

/**
 * Segmented one-time-code input: one box per digit, auto-advance, backspace
 * to go back, arrow keys, paste or SMS/authenticator autofill of the whole
 * code, and `onComplete` when the last digit lands.
 */
export function OtpInput(props: {
  value: string;
  onChange: (value: string) => void;
  onComplete?: (value: string) => void;
  length?: number;
  disabled?: boolean;
  invalid?: boolean;
  autoFocus?: boolean;
  label?: string;
}) {
  const length = props.length ?? 6;
  const refs = useRef<(HTMLInputElement | null)[]>([]);
  const digits = Array.from({ length }, (_, i) => props.value[i] ?? '');

  useEffect(() => {
    if (props.autoFocus) refs.current[0]?.focus();
  }, [props.autoFocus]);

  // After an error the parent clears the value: put the caret back at the start.
  useEffect(() => {
    if (props.value === '' && props.invalid) refs.current[0]?.focus();
  }, [props.value, props.invalid]);

  function commit(next: string, focusIndex: number) {
    const clean = next.replace(/\D/g, '').slice(0, length);
    props.onChange(clean);
    refs.current[Math.min(focusIndex, length - 1)]?.focus();
    if (clean.length === length && clean !== props.value) props.onComplete?.(clean);
  }

  function onInput(i: number, raw: string) {
    const typed = raw.replace(/\D/g, '');
    if (!typed) return;
    // More than one character = paste or one-time-code autofill into this box.
    if (typed.length > 1) return commit(typed.length >= length ? typed : props.value.slice(0, i) + typed, i + typed.length);
    commit(props.value.slice(0, i) + typed + props.value.slice(i + 1), i + 1);
  }

  function onKeyDown(i: number, e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Backspace') {
      e.preventDefault();
      if (digits[i]) props.onChange(props.value.slice(0, i) + props.value.slice(i + 1));
      else if (i > 0) {
        props.onChange(props.value.slice(0, i - 1) + props.value.slice(i));
        refs.current[i - 1]?.focus();
      }
    } else if (e.key === 'ArrowLeft' && i > 0) {
      e.preventDefault();
      refs.current[i - 1]?.focus();
    } else if (e.key === 'ArrowRight' && i < length - 1) {
      e.preventDefault();
      refs.current[i + 1]?.focus();
    }
  }

  function onPaste(e: ClipboardEvent<HTMLInputElement>) {
    e.preventDefault();
    const pasted = e.clipboardData.getData('text').replace(/\D/g, '');
    if (pasted) commit(pasted, pasted.length);
  }

  const half = length / 2;
  return (
    <div role="group" aria-label={props.label ?? 'Verification code'} className={`flex items-center justify-center gap-2 ${props.invalid ? 'animate-shake' : ''}`}>
      {digits.map((d, i) => (
        <div key={i} className="flex items-center gap-2">
          {i === half && Number.isInteger(half) && <span className="h-0.5 w-2.5 rounded bg-slate-300 dark:bg-slate-700" aria-hidden />}
          <input
            ref={(el) => {
              refs.current[i] = el;
            }}
            value={d}
            disabled={props.disabled}
            inputMode="numeric"
            pattern="[0-9]*"
            autoComplete={i === 0 ? 'one-time-code' : 'off'}
            aria-label={`Digit ${i + 1} of ${length}`}
            aria-invalid={props.invalid || undefined}
            maxLength={length}
            onChange={(e) => onInput(i, e.target.value)}
            onKeyDown={(e) => onKeyDown(i, e)}
            onPaste={onPaste}
            onFocus={(e) => e.target.select()}
            className={`h-13 w-11 rounded-xl border bg-white text-center font-mono text-xl font-semibold caret-brand-600 shadow-xs transition outline-none focus:ring-4 disabled:opacity-50 dark:bg-slate-900 ${
              props.invalid
                ? 'border-red-400 text-red-600 focus:border-red-500 focus:ring-red-500/15 dark:border-red-500/60'
                : d
                  ? 'border-brand-500 text-slate-900 focus:ring-brand-500/20 dark:text-slate-100'
                  : 'border-slate-300 focus:border-brand-500 focus:ring-brand-500/20 dark:border-slate-700'
            }`}
          />
        </div>
      ))}
    </div>
  );
}

/** Formats a typed recovery code as XXXXX-XXXXX. */
export function formatRecoveryCode(raw: string): string {
  const clean = raw.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 10);
  return clean.length > 5 ? `${clean.slice(0, 5)}-${clean.slice(5)}` : clean;
}
