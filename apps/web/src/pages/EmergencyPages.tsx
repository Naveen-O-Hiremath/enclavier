import { useEffect, useMemo, useState } from 'react';
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom';
import { AlertTriangle, CheckCircle2, Eye, HeartHandshake } from 'lucide-react';
import type { ItemData } from '@enclavier/shared';
import { acceptEmergencyInvite, openEmergencyVault } from '../lib/security';
import { EmptyState, SecretRow, Spinner } from '../components/ui';
import { errorMessage } from '../components/Toast';

/** /emergency/accept?id=&token= from the invitation e-mail (signed in). */
export function EmergencyAcceptPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const params = useMemo(() => new URLSearchParams(location.search), [location.search]);
  const [state, setState] = useState<'idle' | 'busy' | 'done'>('idle');
  const [error, setError] = useState<string | null>(null);

  async function accept() {
    setState('busy');
    try {
      await acceptEmergencyInvite(params.get('id') ?? '', params.get('token') ?? '');
      setState('done');
    } catch (e) {
      setError(errorMessage(e));
      setState('idle');
    }
  }

  return (
    <div className="mx-auto max-w-md p-6">
      <div className="card p-6 text-center">
        {state === 'done' ? (
          <>
            <CheckCircle2 className="mx-auto h-10 w-10 text-emerald-500" />
            <h1 className="mt-3 text-lg font-semibold">You're an emergency contact</h1>
            <p className="mt-1 text-sm text-slate-500">They still need to confirm you. You'll find them under Settings → Emergency access.</p>
            <button className="btn-primary mt-5" onClick={() => navigate('/settings')}>Open settings</button>
          </>
        ) : (
          <>
            <HeartHandshake className="mx-auto h-10 w-10 text-brand-600" />
            <h1 className="mt-3 text-lg font-semibold">Become an emergency contact</h1>
            <p className="mt-1 text-sm text-slate-500">
              You'll be able to request read-only access to their vault. They're notified and can reject the request during the waiting period.
            </p>
            {error && (
              <p className="mt-4 flex items-center justify-center gap-2 text-sm text-red-600">
                <AlertTriangle className="h-4 w-4" /> {error}
              </p>
            )}
            <button className="btn-primary mt-5 w-full" onClick={accept} disabled={state === 'busy'}>
              {state === 'busy' && <Spinner />} Accept
            </button>
          </>
        )}
      </div>
    </div>
  );
}

/** Read-only view of another person's vault, after emergency access was granted. */
export function EmergencyVaultPage() {
  const { id } = useParams();
  const [vault, setVault] = useState<{ grantorEmail: string; items: { id: string; data: ItemData }[]; unreadable: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);

  useEffect(() => {
    openEmergencyVault(id!).then(setVault, (e) => setError(errorMessage(e)));
  }, [id]);

  if (error) return <EmptyState icon={<AlertTriangle className="h-5 w-5" />} title="Can't open this vault" hint={error} action={<Link className="btn-secondary" to="/settings">Back</Link>} />;
  if (!vault) return <div className="p-6"><Spinner className="h-6 w-6" /></div>;
  const item = vault.items.find((i) => i.id === selected);

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 border-b border-amber-200 bg-amber-50 px-5 py-3 text-sm text-amber-900 dark:border-amber-900/50 dark:bg-amber-950/30 dark:text-amber-200">
        <Eye className="h-4 w-4" /> Emergency read-only access to <strong>{vault.grantorEmail}</strong>'s vault. Every visit is recorded in their audit log.
      </div>
      <div className="flex min-h-0 flex-1">
        <ul className="w-80 shrink-0 divide-y divide-slate-100 overflow-y-auto border-r border-slate-200 dark:divide-slate-800 dark:border-slate-800">
          {vault.items
            .sort((a, b) => a.data.name.localeCompare(b.data.name))
            .map((i) => (
              <li key={i.id}>
                <button className={`w-full px-4 py-2.5 text-left text-sm ${i.id === selected ? 'bg-brand-50 dark:bg-brand-500/10' : 'hover:bg-slate-50 dark:hover:bg-slate-900'}`} onClick={() => setSelected(i.id)}>
                  <div className="truncate font-medium">{i.data.name}</div>
                  <div className="truncate text-xs text-slate-500">{i.data.login?.username ?? i.data.type}</div>
                </button>
              </li>
            ))}
          {vault.unreadable > 0 && <li className="px-4 py-2 text-xs text-red-600">{vault.unreadable} item(s) failed integrity checks</li>}
        </ul>
        <div className="flex-1 overflow-y-auto p-5">
          {!item ? (
            <EmptyState icon={<Eye className="h-5 w-5" />} title="Select an item" />
          ) : (
            <div className="space-y-4">
              <h2 className="text-xl font-semibold">{item.data.name}</h2>
              <div className="card divide-y divide-slate-100 dark:divide-slate-800">
                {item.data.login?.username && <SecretRow label="Username" value={item.data.login.username} />}
                {item.data.login?.password && <SecretRow label="Password" value={item.data.login.password} secret />}
                {item.data.login?.uris?.map((u, n) => <SecretRow key={n} label="Website" value={u} />)}
                {item.data.card?.number && <SecretRow label="Card number" value={item.data.card.number} secret />}
                {item.data.identity?.fullName && <SecretRow label="Full name" value={item.data.identity.fullName} />}
                {item.data.fields?.map((f, n) => <SecretRow key={n} label={f.name || 'Field'} value={f.value} secret={f.hidden} />)}
              </div>
              {item.data.notes && <div className="card p-4 text-sm whitespace-pre-wrap">{item.data.notes}</div>}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
