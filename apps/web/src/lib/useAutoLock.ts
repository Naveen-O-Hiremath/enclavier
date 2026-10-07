import { useEffect } from 'react';
import { useSession } from './session';
import { useSettings } from './settings';
import { effectiveAutoLock, useEffectivePolicy } from './policy';

const ACTIVITY_EVENTS = ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll', 'wheel'] as const;

/** Locks the vault after inactivity (and optionally when the tab is hidden). */
export function useAutoLock(): void {
  const status = useSession((s) => s.status);
  const lock = useSession((s) => s.lock);
  const policy = useEffectivePolicy();
  const minutes = effectiveAutoLock(useSettings((s) => s.autoLockMinutes), policy);
  const lockOnHide = useSettings((s) => s.lockOnHide);

  useEffect(() => {
    if (status !== 'unlocked') return;
    let last = Date.now();
    const touch = () => {
      last = Date.now();
    };
    const onVisibility = () => {
      if (lockOnHide && document.visibilityState === 'hidden') lock();
    };
    ACTIVITY_EVENTS.forEach((e) => window.addEventListener(e, touch, { passive: true }));
    document.addEventListener('visibilitychange', onVisibility);
    // The desktop app raises this when Windows locks, sleeps or the user picks "Lock vault".
    const onHostLock = () => lock();
    window.addEventListener('enclavier:lock', onHostLock);
    const timer =
      minutes > 0
        ? setInterval(() => {
            if (Date.now() - last > minutes * 60_000) lock();
          }, 5_000)
        : undefined;
    return () => {
      ACTIVITY_EVENTS.forEach((e) => window.removeEventListener(e, touch));
      document.removeEventListener('visibilitychange', onVisibility);
      window.removeEventListener('enclavier:lock', onHostLock);
      clearInterval(timer);
    };
  }, [status, minutes, lockOnHide, lock]);
}
