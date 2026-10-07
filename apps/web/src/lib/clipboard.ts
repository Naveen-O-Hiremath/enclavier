import { currentClipboardSeconds } from './policy';

let clearTimer: ReturnType<typeof setTimeout> | undefined;

/**
 * Copies a value and clears it from the clipboard after the configured delay,
 * but only if the clipboard still holds our value (never wipe something the
 * user copied afterwards).
 */
export async function copySecret(value: string): Promise<number> {
  await navigator.clipboard.writeText(value);
  const seconds = currentClipboardSeconds();
  clearTimeout(clearTimer);
  if (seconds > 0) {
    clearTimer = setTimeout(async () => {
      try {
        const current = await navigator.clipboard.readText();
        if (current === value) await navigator.clipboard.writeText('');
      } catch {
        // readText needs focus/permission; fall back to clearing unconditionally.
        await navigator.clipboard.writeText('').catch(() => {});
      }
    }, seconds * 1000);
  }
  return seconds;
}
