import type { TokenResponse } from '@enclavier/shared';

const BASE = (import.meta.env.VITE_API_URL as string | undefined) ?? '';

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

interface TokenStore {
  getAccess(): string | null;
  getRefresh(): string | null;
  save(tokens: TokenResponse): void;
  /** Called when the session can no longer be refreshed (revoked, expired). */
  onSessionLost(): void;
}

let store: TokenStore | null = null;
let refreshing: Promise<boolean> | null = null;

export function configureApi(s: TokenStore): void {
  store = s;
}

async function raw(method: string, path: string, body?: unknown, token?: string | null): Promise<Response> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (token) headers.authorization = `Bearer ${token}`;
  return fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'omit',
    cache: 'no-store',
  });
}

async function doRefresh(): Promise<boolean> {
  // Read the token only after taking the lock: another tab may have rotated it.
  const refreshToken = store?.getRefresh();
  if (!refreshToken) return false;
  const res = await raw('POST', '/api/auth/refresh', { refreshToken });
  if (!res.ok) return false;
  store!.save((await res.json()) as TokenResponse);
  return true;
}

async function refresh(): Promise<boolean> {
  refreshing ??= (async () => {
    try {
      // Refresh tokens are single-use; serialise across tabs so two tabs never
      // present the same token (which the server treats as theft).
      if (navigator.locks) return await navigator.locks.request('enclavier-refresh', doRefresh);
      return await doRefresh();
    } catch {
      return false;
    } finally {
      refreshing = null;
    }
  })();
  return refreshing;
}

async function toError(res: Response): Promise<ApiError> {
  try {
    const body = (await res.json()) as { error?: string; message?: string };
    return new ApiError(res.status, body.error ?? 'error', body.message ?? res.statusText);
  } catch {
    return new ApiError(res.status, 'error', res.statusText || 'Request failed');
  }
}

export async function api<T>(method: string, path: string, body?: unknown, opts: { auth?: boolean } = {}): Promise<T> {
  const auth = opts.auth ?? true;
  let token = auth ? store?.getAccess() : null;
  if (auth && !token && (await refresh())) token = store?.getAccess();

  let res: Response;
  try {
    res = await raw(method, path, body, token);
  } catch {
    throw new ApiError(0, 'network', 'Cannot reach the Enclavier server');
  }
  if (res.status === 401 && auth) {
    if (await refresh()) {
      res = await raw(method, path, body, store?.getAccess());
    }
    if (res.status === 401) {
      store?.onSessionLost();
      throw await toError(res);
    }
  }
  if (!res.ok) throw await toError(res);
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

/** Authenticated GET returning raw text (breach ranges, CSV exports). */
export async function apiText(path: string): Promise<string> {
  let token = store?.getAccess();
  if (!token && (await refresh())) token = store?.getAccess();
  let res = await raw('GET', path, undefined, token);
  if (res.status === 401 && (await refresh())) res = await raw('GET', path, undefined, store?.getAccess());
  if (!res.ok) throw await toError(res);
  return res.text();
}
