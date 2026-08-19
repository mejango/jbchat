"use client";

/**
 * Web-push wakeup subscription. Pushes are payload-free: the keeper
 * sends empty wakeups and the service worker shows a generic
 * notification - message content never rides a push channel.
 */

import { api, getSession } from "./client";

const ENDPOINT_ID_KEY = "jbm-messaging-push-endpoint-v1";
const VAPID_PUBLIC_KEY = process.env.NEXT_PUBLIC_VAPID_PUBLIC_KEY;

export type PushState = "on" | "off" | "denied" | "unavailable";

function applicationServerKey(): Uint8Array | null {
  if (!VAPID_PUBLIC_KEY) return null;
  const padded = VAPID_PUBLIC_KEY.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function supported(): boolean {
  return (
    typeof window !== "undefined" &&
    "serviceWorker" in navigator &&
    "PushManager" in window &&
    "Notification" in window &&
    VAPID_PUBLIC_KEY !== undefined
  );
}

function endpointId(): string {
  let value = window.localStorage.getItem(ENDPOINT_ID_KEY);
  if (!value) {
    value = crypto.randomUUID();
    window.localStorage.setItem(ENDPOINT_ID_KEY, value);
  }
  return value;
}

export async function pushState(): Promise<PushState> {
  if (!supported()) return "unavailable";
  if (Notification.permission === "denied") return "denied";
  const registration = await navigator.serviceWorker.ready;
  const subscription = await registration.pushManager.getSubscription();
  return subscription ? "on" : "off";
}

export async function enablePush(): Promise<PushState> {
  if (!supported()) return "unavailable";
  const session = getSession();
  if (session.status !== "ready" || !session.installationId) return "off";
  const permission = await Notification.requestPermission();
  if (permission !== "granted") return "denied";
  const key = applicationServerKey();
  if (!key) return "unavailable";
  const registration = await navigator.serviceWorker.ready;
  const subscription = await registration.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: key.slice().buffer,
  });
  const json = subscription.toJSON();
  if (!json.endpoint || !json.keys?.p256dh || !json.keys?.auth) {
    await subscription.unsubscribe();
    return "off";
  }
  const response = await api(
    "PUT",
    `/v1/installations/${session.installationId}/push-endpoints/${endpointId()}`,
    {
      provider: "webpush",
      endpoint: json.endpoint,
      keys: { p256dh: json.keys.p256dh, auth: json.keys.auth },
    },
  );
  if (response.status !== 204) {
    await subscription.unsubscribe();
    return "off";
  }
  return "on";
}

export async function disablePush(): Promise<PushState> {
  if (!supported()) return "unavailable";
  const registration = await navigator.serviceWorker.ready;
  const subscription = await registration.pushManager.getSubscription();
  if (subscription) await subscription.unsubscribe();
  const session = getSession();
  if (session.status === "ready" && session.installationId) {
    await api(
      "DELETE",
      `/v1/installations/${session.installationId}/push-endpoints/${endpointId()}`,
    ).catch(() => undefined);
  }
  return "off";
}
