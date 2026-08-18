"use client";

/** Deterministic two-colour identity gradient (juicebox.money family). */
const PALETTE = [
  "#5777EB",
  "#FFBB45",
  "#34C07F",
  "#E86AA4",
  "#8B5CF6",
  "#F97316",
  "#0EA5E9",
];

export function identityGradient(address: string): string {
  const value = address.toLowerCase();
  let hash = 0;
  for (let index = 0; index < value.length; index += 1) {
    hash = (hash << 5) - hash + value.charCodeAt(index);
    hash |= 0;
  }
  const first = PALETTE[Math.abs(hash) % PALETTE.length];
  const second = PALETTE[Math.abs(hash >> 3) % PALETTE.length];
  return `linear-gradient(135deg, ${first}, ${second})`;
}

export function truncateAddress(address: string): string {
  return `${address.slice(0, 6)}…${address.slice(-4)}`;
}

const VIEW_AS_KEY = "jbm-messaging-view-as-v1";
type Listener = () => void;
const listeners = new Set<Listener>();

function emit(): void {
  for (const listener of listeners) listener();
}

export function getViewAs(): string | null {
  if (typeof window === "undefined") return null;
  const value = window.localStorage.getItem(VIEW_AS_KEY);
  return value && /^0x[0-9a-fA-F]{40}$/.test(value) ? value.toLowerCase() : null;
}

export function setViewAs(address: string): void {
  window.localStorage.setItem(VIEW_AS_KEY, address.toLowerCase());
  emit();
}

export function clearViewAs(): void {
  window.localStorage.removeItem(VIEW_AS_KEY);
  emit();
}

export function subscribeViewAs(listener: Listener): () => void {
  listeners.add(listener);
  const onStorage = (event: StorageEvent) => {
    if (event.key === VIEW_AS_KEY) listener();
  };
  window.addEventListener("storage", onStorage);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("storage", onStorage);
  };
}

export function getViewAsServerSnapshot(): string | null {
  return null;
}
