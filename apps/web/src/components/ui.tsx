import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Copy, ExternalLink, Eye, EyeOff, Lock, X } from 'lucide-react';
import { strengthScore } from '@enclavier/crypto';
import { copySecret } from '../lib/clipboard';
import { toast } from './Toast';

export function Logo({ size = 'md' }: { size?: 'md' | 'lg' }) {
  const box = size === 'lg' ? 'h-12 w-12' : 'h-9 w-9';
  return (
    <div className="flex items-center gap-2.5">
      {/* The mark sits on its own dark tile, so it reads the same in light and dark themes. */}
      <img src="/logo.png" alt="" className={`${box} rounded-[22%] shadow-sm dark:ring-1 dark:ring-white/15`} />
      <span className={`${size === 'lg' ? 'text-2xl' : 'text-lg'} font-semibold tracking-tight`}>Enclavier</span>
    </div>
  );
}

export function Spinner({ className = 'h-4 w-4' }: { className?: string }) {
  return <span className={`${className} inline-block animate-spin rounded-full border-2 border-current border-r-transparent`} />;
}

export function PasswordInput(props: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  autoFocus?: boolean;
  autoComplete?: string;
  id?: string;
  mono?: boolean;
}) {
  const [visible, setVisible] = useState(false);
  return (
    <div className="relative">
      <input
        id={props.id}
        className={`input pr-10 ${props.mono && visible ? 'font-mono' : ''}`}
        type={visible ? 'text' : 'password'}
        value={props.value}
        onChange={(e) => props.onChange(e.target.value)}
        placeholder={props.placeholder}
        autoFocus={props.autoFocus}
        autoComplete={props.autoComplete ?? 'off'}
        spellCheck={false}
      />
      <button
        type="button"
        className="icon-btn absolute top-1/2 right-1 -translate-y-1/2"
        onClick={() => setVisible((v) => !v)}
        aria-label={visible ? 'Hide' : 'Show'}
        tabIndex={-1}
      >
        {visible ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
      </button>
    </div>
  );
}

const STRENGTH = [
  { label: 'Very weak', color: 'bg-red-500' },
  { label: 'Weak', color: 'bg-orange-500' },
  { label: 'Fair', color: 'bg-amber-500' },
  { label: 'Strong', color: 'bg-lime-500' },
  { label: 'Very strong', color: 'bg-emerald-500' },
];

export function StrengthMeter({ password }: { password: string }) {
  if (!password) return null;
  const score = strengthScore(password);
  const s = STRENGTH[score]!;
  return (
    <div className="mt-2 flex items-center gap-3">
      <div className="flex flex-1 gap-1">
        {[0, 1, 2, 3, 4].map((i) => (
          <div key={i} className={`h-1.5 flex-1 rounded-full ${i <= score ? s.color : 'bg-slate-200 dark:bg-slate-800'}`} />
        ))}
      </div>
      <span className="w-20 text-right text-xs text-slate-500">{s.label}</span>
    </div>
  );
}

export async function copyWithToast(value: string, what: string): Promise<void> {
  try {
    const seconds = await copySecret(value);
    toast(seconds > 0 ? `${what} copied · clears in ${seconds}s` : `${what} copied`);
  } catch {
    toast('Clipboard is unavailable', 'error');
  }
}

export function Modal(props: { title: string; onClose: () => void; children: ReactNode; footer?: ReactNode; wide?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && props.onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [props.onClose]);
  return (
    <div
      className="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-slate-950/40 p-4 backdrop-blur-sm sm:items-center"
      onMouseDown={(e) => e.target === e.currentTarget && props.onClose()}
    >
      <div ref={ref} role="dialog" aria-modal="true" className={`card w-full ${props.wide ? 'max-w-2xl' : 'max-w-md'} shadow-xl`}>
        <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3.5 dark:border-slate-800">
          <h2 className="font-semibold">{props.title}</h2>
          <button className="icon-btn" onClick={props.onClose} aria-label="Close">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="max-h-[70vh] overflow-y-auto px-5 py-4">{props.children}</div>
        {props.footer && (
          <div className="flex justify-end gap-2 border-t border-slate-200 px-5 py-3 dark:border-slate-800">{props.footer}</div>
        )}
      </div>
    </div>
  );
}

/** Read-only field row with reveal + copy, used on the item detail view. */
export function SecretRow(props: { label: string; value: string; secret?: boolean; mono?: boolean; href?: string; masked?: boolean }) {
  const [shown, setShown] = useState(!props.secret);
  if (props.masked) {
    return (
      <div className="flex items-center gap-3 px-4 py-3" title="Your organization only lets you use this item, not view its secrets">
        <div className="min-w-0 flex-1">
          <div className="text-xs text-slate-500">{props.label}</div>
          <div className="font-mono text-sm text-slate-400">••••••••••••</div>
        </div>
        <Lock className="mr-2 h-4 w-4 text-slate-400" />
      </div>
    );
  }
  return (
    <div className="group flex items-center gap-3 px-4 py-3">
      <div className="min-w-0 flex-1">
        <div className="text-xs text-slate-500">{props.label}</div>
        <div className={`truncate text-sm ${props.mono || props.secret ? 'font-mono' : ''}`}>
          {props.href ? (
            <a href={props.href} target="_blank" rel="noopener noreferrer" className="text-brand-600 hover:underline dark:text-brand-400">
              {props.value}
            </a>
          ) : shown ? (
            props.value
          ) : (
            '•'.repeat(Math.min(props.value.length, 16))
          )}
        </div>
      </div>
      {props.secret && (
        <button className="icon-btn" onClick={() => setShown((v) => !v)} aria-label={shown ? 'Hide' : 'Reveal'}>
          {shown ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
        </button>
      )}
      {props.href && (
        <a className="icon-btn" href={props.href} target="_blank" rel="noopener noreferrer" title="Launch website" aria-label={`Open ${props.label}`}>
          <ExternalLink className="h-4 w-4" />
        </a>
      )}
      <button className="icon-btn" onClick={() => copyWithToast(props.value, props.label)} aria-label={`Copy ${props.label}`}>
        <Copy className="h-4 w-4" />
      </button>
    </div>
  );
}

export function EmptyState(props: { icon: ReactNode; title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-3 p-8 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-slate-100 text-slate-400 dark:bg-slate-800">
        {props.icon}
      </div>
      <div>
        <div className="font-medium">{props.title}</div>
        {props.hint && <div className="mt-1 text-sm text-slate-500">{props.hint}</div>}
      </div>
      {props.action}
    </div>
  );
}
