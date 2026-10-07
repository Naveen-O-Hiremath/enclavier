import { useEffect, useMemo, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { AlertTriangle, Building2, CheckCircle2 } from 'lucide-react';
import type { InvitePreview } from '@enclavier/shared';
import { acceptInvite, loadPendingInvite, previewInvite, readInviteFromUrl, savePendingInvite } from '../lib/orgs';
import { useSession } from '../lib/session';
import { Logo, Spinner } from '../components/ui';
import { errorMessage } from '../components/Toast';

/**
 * Handles /accept-invite links from invitation e-mails. Logged-out visitors
 * are sent to sign in or register (the invite is remembered for this tab),
 * signed-in users accept directly.
 */
export function AcceptInvitePage() {
  const location = useLocation();
  const navigate = useNavigate();
  const { status, profile } = useSession();
  const invite = useMemo(() => readInviteFromUrl(location.search) ?? loadPendingInvite(), [location.search]);
  const [preview, setPreview] = useState<InvitePreview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  useEffect(() => {
    if (!invite) return setError('This invitation link is incomplete.');
    savePendingInvite(invite);
    previewInvite(invite).then(setPreview, (e) => {
      savePendingInvite(null);
      setError(errorMessage(e));
    });
  }, [invite]);

  async function accept() {
    if (!invite) return;
    setBusy(true);
    setError(null);
    try {
      await acceptInvite(invite);
      setDone(true);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  const wrongAccount = status === 'unlocked' && preview && profile && preview.email !== profile.email;

  return (
    <div className="flex min-h-full items-center justify-center bg-gradient-to-b from-brand-50 to-slate-50 px-4 py-12 dark:from-slate-900 dark:to-slate-950">
      <div className="w-full max-w-md">
        <div className="mb-8 flex justify-center">
          <Logo size="lg" />
        </div>
        <div className="card p-6 text-center shadow-lg">
          {error ? (
            <>
              <AlertTriangle className="mx-auto h-10 w-10 text-amber-500" />
              <h1 className="mt-3 text-lg font-semibold">Invitation unavailable</h1>
              <p className="mt-1 text-sm text-slate-500">{error}</p>
              <Link to="/" className="btn-secondary mt-5">Go to vault</Link>
            </>
          ) : !preview ? (
            <Spinner className="h-6 w-6" />
          ) : done ? (
            <>
              <CheckCircle2 className="mx-auto h-10 w-10 text-emerald-500" />
              <h1 className="mt-3 text-lg font-semibold">You joined {preview.orgName}</h1>
              <p className="mt-1 text-sm text-slate-500">
                An administrator now needs to confirm your membership. Shared collections appear in your vault as soon as they do.
              </p>
              <button className="btn-primary mt-5" onClick={() => navigate('/vault')}>Open vault</button>
            </>
          ) : (
            <>
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-brand-50 text-brand-600 dark:bg-brand-500/10">
                <Building2 className="h-6 w-6" />
              </div>
              <h1 className="mt-3 text-lg font-semibold">Join {preview.orgName}</h1>
              <p className="mt-1 text-sm text-slate-500">
                {preview.inviterName ?? 'An administrator'} invited <strong>{preview.email}</strong> to share passwords and secrets on Enclavier.
              </p>
              {status === 'unlocked' ? (
                <>
                {wrongAccount ? (
                  <p className="mt-5 rounded-lg bg-amber-50 p-3 text-sm text-amber-800 dark:bg-amber-950/40 dark:text-amber-200">
                    You are signed in as {profile!.email}. Log out and sign in as {preview.email} to accept.
                  </p>
                ) : (
                  <button className="btn-primary mt-5 w-full" onClick={accept} disabled={busy}>
                    {busy && <Spinner />} Accept invitation
                  </button>
                )}
                <button
                  className="btn-ghost mt-2 w-full"
                  onClick={() => {
                    savePendingInvite(null);
                    navigate('/vault');
                  }}
                >
                  Not now
                </button>
                </>
              ) : (
                <div className="mt-5 flex flex-col gap-2">
                  <Link to={`/register?email=${encodeURIComponent(preview.email)}`} className="btn-primary">Create account</Link>
                  <Link to="/" className="btn-secondary">I already have an account</Link>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
