import { create } from 'zustand';

export interface Settings {
  /** Minutes of inactivity before the vault locks. 0 = never. */
  autoLockMinutes: number;
  /** Seconds before copied secrets are cleared from the clipboard. 0 = never. */
  clipboardClearSeconds: number;
  lockOnHide: boolean;
}

const KEY = 'enclavier.settings';
const DEFAULTS: Settings = { autoLockMinutes: 15, clipboardClearSeconds: 30, lockOnHide: false };

function load(): Settings {
  try {
    return { ...DEFAULTS, ...(JSON.parse(localStorage.getItem(KEY) ?? '{}') as Partial<Settings>) };
  } catch {
    return DEFAULTS;
  }
}

export const useSettings = create<Settings & { update: (patch: Partial<Settings>) => void }>((set, get) => ({
  ...load(),
  update: (patch) => {
    set(patch);
    const { update: _u, ...rest } = { ...get() };
    localStorage.setItem(KEY, JSON.stringify(rest));
  },
}));
