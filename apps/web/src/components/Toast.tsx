import { CheckCircle2, AlertTriangle } from 'lucide-react';
import { create } from 'zustand';

interface ToastItem {
  id: number;
  message: string;
  tone: 'success' | 'error';
}

const useToasts = create<{ toasts: ToastItem[] }>(() => ({ toasts: [] }));
let nextId = 1;

export function toast(message: string, tone: ToastItem['tone'] = 'success'): void {
  const id = nextId++;
  useToasts.setState((s) => ({ toasts: [...s.toasts, { id, message, tone }] }));
  setTimeout(() => useToasts.setState((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })), 3500);
}

export function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : 'Something went wrong';
}

export function Toaster() {
  const toasts = useToasts((s) => s.toasts);
  return (
    <div className="pointer-events-none fixed right-4 bottom-4 z-50 flex flex-col gap-2" aria-live="polite">
      {toasts.map((t) => (
        <div
          key={t.id}
          className="card pointer-events-auto flex items-center gap-2.5 px-4 py-3 text-sm shadow-lg"
          role={t.tone === 'error' ? 'alert' : 'status'}
        >
          {t.tone === 'success' ? (
            <CheckCircle2 className="h-4 w-4 text-emerald-500" />
          ) : (
            <AlertTriangle className="h-4 w-4 text-red-500" />
          )}
          {t.message}
        </div>
      ))}
    </div>
  );
}
