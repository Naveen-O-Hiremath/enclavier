import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react';
import {
  ArrowRight,
  Copy,
  CreditCard,
  ExternalLink,
  Eye,
  EyeOff,
  FileText,
  Globe,
  KeyRound,
  Lock,
  LogOut,
  RefreshCw,
  Search,
  Settings,
  Shield,
  Sparkles,
  UserSquare,
  Wand2,
} from 'lucide-react';
import { DEFAULT_PASSWORD_OPTIONS, type PasswordOptions } from '@enclavier/crypto';
import type { TwoFactorMethod } from '@enclavier/shared';
import { send, type CopyField, type ExtState, type ItemSummary } from '../shared/messages';

// ---- small pieces ------------------------------------------------------------------------------

function Spinner() {
  return <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-current border-r-transparent" />;
}

function ErrorLine({ message }: { message: string | null }) {
  if (!message) return null;
  return <p className="rounded-lg bg-red-50 px-3 py-2 text-xs text-red-700 dark:bg-red-950/50 dark:text-red-300">{message}</p>;
}

function Brand({ subtitle }: { subtitle?: string }) {
  return (
    <div className="flex flex-col items-center gap-2 pt-6 pb-4">
      <img src="icons/128.png" alt="" className="h-12 w-12 rounded-[22%] shadow dark:ring-1 dark:ring-white/15" />
      <div className="text-base font-semibold">Enclavier</div>
      {subtitle && <div className="text-center text-xs text-slate-500">{subtitle}</div>}
    </div>
  );
}

const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e));

function useToast() {
  const [msg, setMsg] = useState<string | null>(null);
  const show = useCallback((m: string) => {
    setMsg(m);
    setTimeout(() => setMsg(null), 1800);
  }, []);
  const node = msg ? (
    <div className="pointer-events-none fixed inset-x-0 bottom-3 flex justify-center">
      <div className="rounded-lg bg-slate-900 px-3 py-1.5 text-xs text-white shadow-lg dark:bg-slate-100 dark:text-slate-900">{msg}</div>
    </div>
  ) : null;
  return { show, node };
}

// ---- screens -------------------------------------------------------------------------------------

function LoginScreen({ state, onDone }: { state: ExtState; onDone: () => void }) {
  const [server, setServer] = useState(state.serverUrl ?? 'https://');
  const [email, setEmail] = useState(state.email ?? '');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const url = new URL(server.trim());
      if (url.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(url.hostname)) {
        throw new Error('Use an https:// server address (http is allowed only for localhost).');
      }
      const login = () => send({ type: 'login', serverUrl: url.origin, email, password });
      try {
        await login();
      } catch (err) {
        // Firefox grants host access per site: ask for exactly this server, then retry once.
        const origins = [`${url.origin}/*`];
        if (!/Cannot reach/.test(errorText(err)) || (await chrome.permissions.contains({ origins }))) throw err;
        if (!(await chrome.permissions.request({ origins }))) throw new Error('Enclavier needs permission to talk to your server.');
        await login();
      }
      setPassword('');
      onDone();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-3 px-5 pb-5">
      <Brand subtitle="Sign in with your master password. It never leaves this browser." />
      <ErrorLine message={error} />
      <div>
        <label className="label">Server</label>
        <input className="input" value={server} onChange={(e) => setServer(e.target.value)} placeholder="https://vault.example.com" required />
      </div>
      <div>
        <label className="label">E-mail</label>
        <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoFocus required />
      </div>
      <div>
        <label className="label">Master password</label>
        <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
      </div>
      <button className="btn-primary w-full" disabled={busy}>
        {busy ? <Spinner /> : <ArrowRight className="h-4 w-4" />} {busy ? 'Deriving keys…' : 'Sign in'}
      </button>
      <p className="text-center text-[11px] text-slate-500">Organization requires SSO? Sign in to the web vault; SSO in the extension is coming.</p>
    </form>
  );
}

function TwoFactorScreen({ state, onDone }: { state: ExtState; onDone: () => void }) {
  const methods = state.twoFactor?.methods ?? [];
  const [method, setMethod] = useState<TwoFactorMethod>(methods.includes('totp') ? 'totp' : 'recovery');
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await send({ type: 'login2fa', method, code: code.trim() });
      onDone();
    } catch (err) {
      setError(errorText(err));
      setCode('');
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-3 px-5 pb-5">
      <Brand subtitle={`Two-step login for ${state.email}`} />
      <ErrorLine message={error} />
      {state.twoFactor?.webauthn && methods.length === 1 && (
        <p className="rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:bg-amber-950/40 dark:text-amber-200">
          Security keys can't be used inside the extension. Use a recovery code, or add an authenticator app in the web vault.
        </p>
      )}
      <div>
        <label className="label">{method === 'totp' ? 'Authenticator code' : 'Recovery code'}</label>
        <input className="input text-center font-mono tracking-widest" value={code} onChange={(e) => setCode(e.target.value)} autoFocus autoComplete="one-time-code" />
      </div>
      <button className="btn-primary w-full" disabled={busy || code.trim().length < 6}>
        {busy && <Spinner />} Verify
      </button>
      <div className="flex justify-between text-xs">
        {methods.length > 1 && (
          <button type="button" className="text-brand-600 hover:underline" onClick={() => setMethod(method === 'totp' ? 'recovery' : 'totp')}>
            {method === 'totp' ? 'Use a recovery code' : 'Use an authenticator app'}
          </button>
        )}
        <button type="button" className="text-slate-500 hover:underline" onClick={() => send({ type: 'cancel2fa' }).then(onDone)}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function UnlockScreen({ state, onDone }: { state: ExtState; onDone: () => void }) {
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await send({ type: 'unlock', password });
      onDone();
    } catch (err) {
      setError(errorText(err));
      setPassword('');
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-3 px-5 pb-5">
      <Brand subtitle={`Locked · ${state.email}`} />
      <ErrorLine message={error} />
      <input className="input" type="password" placeholder="Master password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
      <button className="btn-primary w-full" disabled={busy || !password}>
        {busy ? <Spinner /> : <Lock className="h-4 w-4" />} {busy ? 'Unlocking…' : 'Unlock'}
      </button>
      <button type="button" className="btn-ghost w-full text-xs" onClick={() => send({ type: 'logout' }).then(onDone)}>
        <LogOut className="h-3.5 w-3.5" /> Log out
      </button>
    </form>
  );
}

// ---- vault -------------------------------------------------------------------------------------------

const TYPE_ICON = { login: Globe, note: FileText, card: CreditCard, identity: UserSquare } as const;

function ItemRow({ item, toast, onChanged }: { item: ItemSummary; toast: (m: string) => void; onChanged: () => void }) {
  const Icon = TYPE_ICON[item.type];
  const [busy, setBusy] = useState(false);

  async function act(fn: () => Promise<unknown>, done?: string) {
    setBusy(true);
    try {
      await fn();
      if (done) toast(done);
    } catch (e) {
      toast(errorText(e));
    } finally {
      setBusy(false);
      onChanged();
    }
  }

  const copy = (field: CopyField, label: string) =>
    act(async () => {
      const value = await send<string>({ type: 'copy', id: item.id, field });
      await navigator.clipboard.writeText(value);
    }, `${label} copied`);

  return (
    <li className="group flex items-center gap-2.5 px-3 py-2 hover:bg-white dark:hover:bg-slate-900">
      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-brand-50 text-brand-600 dark:bg-brand-500/10 dark:text-brand-400">
        <Icon className="h-4 w-4" />
      </div>
      <button
        className="min-w-0 flex-1 text-left"
        disabled={busy || item.type !== 'login' || !item.match}
        title={item.match ? 'Fill on this page' : undefined}
        onClick={() => act(async () => {
          await send({ type: 'fill', id: item.id });
          window.close();
        })}
      >
        <div className="truncate text-sm font-medium">{item.name}</div>
        <div className="truncate text-xs text-slate-500">
          {item.org && <span className="mr-1 rounded bg-slate-200/70 px-1 text-[10px] dark:bg-slate-800">{item.org}</span>}
          {item.username || item.uri || '—'}
        </div>
      </button>
      <div className="flex items-center">
        {item.type === 'login' && item.match && (
          <button className="icon-btn text-brand-600" title="Fill" disabled={busy} onClick={() => act(async () => { await send({ type: 'fill', id: item.id }); window.close(); })}>
            <Wand2 className="h-4 w-4" />
          </button>
        )}
        {item.username && (
          <button className="icon-btn" title="Copy username" disabled={busy} onClick={() => copy('username', 'Username')}>
            <UserSquare className="h-4 w-4" />
          </button>
        )}
        {item.hasPassword && item.permission !== 'use' && (
          <button className="icon-btn" title="Copy password" disabled={busy} onClick={() => copy('password', 'Password')}>
            <KeyRound className="h-4 w-4" />
          </button>
        )}
        {item.hasTotp && (
          <button className="icon-btn" title="Copy verification code" disabled={busy} onClick={() => copy('totp', 'Code')}>
            <Copy className="h-4 w-4" />
          </button>
        )}
        {item.uri && (
          <button className="icon-btn" title="Launch and fill" disabled={busy} onClick={() => act(() => send({ type: 'launch', id: item.id }))}>
            <ExternalLink className="h-4 w-4" />
          </button>
        )}
      </div>
    </li>
  );
}

function VaultTab({ toast }: { toast: (m: string) => void }) {
  const [items, setItems] = useState<ItemSummary[] | null>(null);
  const [query, setQuery] = useState('');
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => send<ItemSummary[]>({ type: 'items' }).then(setItems, (e) => setError(errorText(e))), []);
  useEffect(() => void load(), [load]);

  const q = query.trim().toLowerCase();
  const matches = useMemo(() => (items ?? []).filter((i) => i.match), [items]);
  const results = useMemo(
    () => (q ? (items ?? []).filter((i) => [i.name, i.username, i.uri ?? '', i.org ?? ''].some((v) => v.toLowerCase().includes(q))) : []),
    [items, q],
  );

  if (!items) return <div className="flex justify-center p-6">{error ? <ErrorLine message={error} /> : <Spinner />}</div>;
  return (
    <div>
      <div className="relative p-3 pb-2">
        <Search className="absolute top-1/2 left-6 h-4 w-4 -translate-y-1/2 text-slate-400" />
        <input className="input pl-9" placeholder="Search vault" value={query} onChange={(e) => setQuery(e.target.value)} autoFocus />
      </div>
      {q ? (
        <Section title={`${results.length} result${results.length === 1 ? '' : 's'}`}>
          {results.slice(0, 50).map((i) => <ItemRow key={i.id} item={i} toast={toast} onChanged={load} />)}
        </Section>
      ) : (
        <>
          <Section title="This site">
            {matches.length === 0 ? (
              <li className="px-4 py-3 text-xs text-slate-500">No logins for this page. Search above, or sign in here and Enclavier offers to save it.</li>
            ) : (
              matches.map((i) => <ItemRow key={i.id} item={i} toast={toast} onChanged={load} />)
            )}
          </Section>
          <Section title="Favorites">
            {items.filter((i) => i.favorite && !i.match).slice(0, 20).map((i) => <ItemRow key={i.id} item={i} toast={toast} onChanged={load} />)}
          </Section>
        </>
      )}
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  const empty = Array.isArray(children) && children.length === 0;
  if (empty) return null;
  return (
    <div className="pb-2">
      <div className="px-4 pt-1 pb-1 text-[11px] font-semibold tracking-wide text-slate-500 uppercase">{title}</div>
      <ul className="divide-y divide-slate-100 dark:divide-slate-800/70">{children}</ul>
    </div>
  );
}

function GeneratorTab({ toast }: { toast: (m: string) => void }) {
  const [opts, setOpts] = useState<PasswordOptions>({ ...DEFAULT_PASSWORD_OPTIONS, length: 20 });
  const [value, setValue] = useState('');
  const [shown, setShown] = useState(true);
  const regen = useCallback((o: PasswordOptions) => send<string>({ type: 'generate', options: o }).then(setValue, (e) => toast(errorText(e))), [toast]);
  useEffect(() => void regen(opts), [opts, regen]);

  const flag = (k: keyof PasswordOptions, label: string) => (
    <label className="flex items-center gap-2 text-sm">
      <input type="checkbox" checked={!!opts[k]} onChange={(e) => setOpts({ ...opts, [k]: e.target.checked })} /> {label}
    </label>
  );

  return (
    <div className="space-y-4 p-4">
      <div className="flex items-center gap-2 rounded-lg border border-slate-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-900">
        <code className="min-w-0 flex-1 font-mono text-sm break-all">{shown ? value : '•'.repeat(value.length)}</code>
        <button className="icon-btn" title={shown ? 'Hide' : 'Show'} onClick={() => setShown(!shown)}>{shown ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button>
        <button className="icon-btn" title="Regenerate" onClick={() => regen(opts)}><RefreshCw className="h-4 w-4" /></button>
        <button className="icon-btn" title="Copy" onClick={() => navigator.clipboard.writeText(value).then(() => toast('Password copied'))}><Copy className="h-4 w-4" /></button>
      </div>
      <div>
        <label className="label">Length · {opts.length}</label>
        <input type="range" min={8} max={64} value={opts.length} onChange={(e) => setOpts({ ...opts, length: Number(e.target.value) })} className="w-full accent-brand-600" />
      </div>
      <div className="grid grid-cols-2 gap-2">
        {flag('uppercase', 'A–Z')}
        {flag('lowercase', 'a–z')}
        {flag('digits', '0–9')}
        {flag('symbols', '!@#$')}
      </div>
    </div>
  );
}

function SettingsTab({ state, onChanged }: { state: ExtState; onChanged: () => void }) {
  const shortcut = navigator.userAgent.includes('Mac') ? '⌘⇧L' : 'Ctrl+Shift+L';
  return (
    <div className="space-y-4 p-4 text-sm">
      <div>
        <div className="font-medium">{state.name}</div>
        <div className="text-xs text-slate-500">{state.email}</div>
        <div className="truncate text-xs text-slate-500">{state.serverUrl}</div>
      </div>
      <div>
        <label className="label">Lock after inactivity</label>
        <select className="input" value={state.lockMinutes} onChange={(e) => send({ type: 'setLockMinutes', minutes: Number(e.target.value) }).then(onChanged)}>
          {[1, 5, 15, 30, 60, 240].map((m) => (
            <option key={m} value={m}>{m < 60 ? `${m} minute${m === 1 ? '' : 's'}` : `${m / 60} hour${m === 60 ? '' : 's'}`}</option>
          ))}
          <option value={0}>When the browser closes</option>
        </select>
        <p className="mt-1 text-xs text-slate-500">Also locks when your computer locks. Organization policies may shorten this.</p>
      </div>
      <p className="rounded-lg bg-slate-100 p-3 text-xs text-slate-600 dark:bg-slate-900 dark:text-slate-300">
        <Sparkles className="mr-1 inline h-3.5 w-3.5" /> Press <kbd className="rounded bg-white px-1 font-mono dark:bg-slate-800">{shortcut}</kbd> on a sign-in page to fill
        the best match, or click the Enclavier icon inside a login field.
      </p>
      <div className="grid grid-cols-2 gap-2">
        <button className="btn-secondary" onClick={() => send({ type: 'openVault' })}><ExternalLink className="h-4 w-4" /> Web vault</button>
        <button className="btn-secondary" onClick={() => send({ type: 'sync' }).then(onChanged)}><RefreshCw className="h-4 w-4" /> Sync</button>
        <button className="btn-secondary" onClick={() => send({ type: 'lock' }).then(onChanged)}><Lock className="h-4 w-4" /> Lock</button>
        <button className="btn-secondary" onClick={() => send({ type: 'logout' }).then(onChanged)}><LogOut className="h-4 w-4" /> Log out</button>
      </div>
    </div>
  );
}

function Unlocked({ state, onChanged }: { state: ExtState; onChanged: () => void }) {
  const [tab, setTab] = useState<'vault' | 'generator' | 'settings'>('vault');
  const { show, node } = useToast();
  const TABS = [
    { id: 'vault', label: 'Vault', icon: Shield },
    { id: 'generator', label: 'Generator', icon: Wand2 },
    { id: 'settings', label: 'Settings', icon: Settings },
  ] as const;
  return (
    <div className="flex h-[540px] flex-col">
      <header className="flex items-center gap-2 border-b border-slate-200 px-3 py-2 dark:border-slate-800">
        <img src="icons/128.png" alt="" className="h-7 w-7 rounded-[22%] dark:ring-1 dark:ring-white/15" />
        <div className="flex-1 text-sm font-semibold">Enclavier</div>
        <button className="icon-btn" title="Lock" onClick={() => send({ type: 'lock' }).then(onChanged)}><Lock className="h-4 w-4" /></button>
      </header>
      <main className="min-h-0 flex-1 overflow-y-auto">
        {tab === 'vault' && <VaultTab toast={show} />}
        {tab === 'generator' && <GeneratorTab toast={show} />}
        {tab === 'settings' && <SettingsTab state={state} onChanged={onChanged} />}
      </main>
      <nav className="grid grid-cols-3 border-t border-slate-200 dark:border-slate-800">
        {TABS.map((t) => (
          <button key={t.id} className={`flex flex-col items-center gap-0.5 py-2 text-[11px] ${tab === t.id ? 'text-brand-600 dark:text-brand-400' : 'text-slate-500'}`} onClick={() => setTab(t.id)}>
            <t.icon className="h-4 w-4" /> {t.label}
          </button>
        ))}
      </nav>
      {node}
    </div>
  );
}

export function App() {
  const [state, setState] = useState<ExtState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const refresh = useCallback(() => send<ExtState>({ type: 'state' }).then(setState, (e) => setError(errorText(e))), []);
  useEffect(() => void refresh(), [refresh]);

  if (!state) return <div className="flex justify-center p-8">{error ? <ErrorLine message={error} /> : <Spinner />}</div>;
  if (state.twoFactor) return <TwoFactorScreen state={state} onDone={refresh} />;
  if (state.status === 'loggedOut') return <LoginScreen state={state} onDone={refresh} />;
  if (state.status === 'locked') return <UnlockScreen state={state} onDone={refresh} />;
  return <Unlocked state={state} onChanged={refresh} />;
}
