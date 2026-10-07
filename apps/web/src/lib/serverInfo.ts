import { useEffect, useState } from 'react';
import { api } from './api';

export interface ServerInfo {
  name: string;
  version: string;
  /** Sign-up is open, or this is a new install waiting for its first account. */
  signupsEnabled: boolean;
  setupRequired: boolean;
}

let cached: Promise<ServerInfo> | null = null;

/** Public server facts (no sign-in needed). Null while loading or if the server is unreachable. */
export function useServerInfo(): ServerInfo | null {
  const [info, setInfo] = useState<ServerInfo | null>(null);
  useEffect(() => {
    let alive = true;
    cached ??= api<ServerInfo>('GET', '/api/server-info', undefined, { auth: false });
    cached.then(
      (i) => alive && setInfo(i),
      () => {
        cached = null;
      },
    );
    return () => {
      alive = false;
    };
  }, []);
  return info;
}

/** After the first account is created the answer changes. */
export function forgetServerInfo() {
  cached = null;
}
