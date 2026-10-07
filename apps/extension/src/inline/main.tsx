import { StrictMode, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Globe, Lock, X } from 'lucide-react';
import '../popup/styles.css';
import { send, type ItemSummary } from '../shared/messages';

/**
 * The in-page login picker. It is an extension page loaded in an iframe, so
 * the website around it can't read the list (different origin). It only ever
 * receives names and usernames of logins that match the page.
 */
function Inline() {
  const [data, setData] = useState<{ locked: boolean; items: ItemSummary[] } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    send<{ locked: boolean; items: ItemSummary[] }>({ type: 'inlineItems' }).then(setData, (e: Error) => setError(e.message));
  }, []);

  const close = () => void send({ type: 'inlineClose' });

  return (
    <div className="flex h-screen flex-col bg-white text-slate-900 dark:bg-slate-900 dark:text-slate-100">
      <header className="flex items-center gap-2 border-b border-slate-100 px-3 py-2 dark:border-slate-800">
        <img src="icons/32.png" alt="" className="h-4 w-4 rounded-[22%]" />
        <span className="flex-1 text-xs font-semibold">Enclavier</span>
        <button className="icon-btn" title="Close" onClick={close}><X className="h-3.5 w-3.5" /></button>
      </header>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {error && <p className="p-3 text-xs text-red-600">{error}</p>}
        {data?.locked && (
          <div className="flex flex-col items-center gap-2 p-5 text-center text-xs text-slate-500">
            <Lock className="h-5 w-5" />
            Your vault is locked. Click the Enclavier button in the toolbar to unlock it.
          </div>
        )}
        {data && !data.locked && data.items.length === 0 && <p className="p-4 text-center text-xs text-slate-500">No saved logins for this site.</p>}
        <ul>
          {data?.items.map((i) => (
            <li key={i.id}>
              <button
                className="flex w-full items-center gap-2.5 px-3 py-2 text-left hover:bg-brand-50 dark:hover:bg-slate-800"
                onClick={() => send({ type: 'inlineFill', id: i.id }).catch((e: Error) => setError(e.message))}
              >
                <Globe className="h-4 w-4 shrink-0 text-brand-600" />
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-medium">{i.name}</span>
                  <span className="block truncate text-xs text-slate-500">{i.username || '(no username)'}</span>
                </span>
              </button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Inline />
  </StrictMode>,
);
