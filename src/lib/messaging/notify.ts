import { api } from "./client";

/**
 * Out-of-band notification channels (email / Telegram / WhatsApp). Browser
 * web-push stays in push.ts. These are account-scoped and verified: email
 * by a code, Telegram by tapping a deep link.
 */

export type ChannelKind = "email" | "telegram" | "whatsapp";

export interface NotificationChannel {
  channelId: string;
  kind: ChannelKind;
  display: string;
  state: "pending" | "active" | "disabled";
  createdAt: string;
}

export interface ChannelsView {
  channels: NotificationChannel[];
  providers: { email: boolean; telegram: boolean; whatsapp: boolean };
}

export async function listChannels(): Promise<ChannelsView> {
  const response = await api("GET", "/v1/notification-channels");
  if (!response.ok) return { channels: [], providers: { email: false, telegram: false, whatsapp: false } };
  return (await response.json()) as ChannelsView;
}

export type CreateChannelResult =
  | { status: "code_sent"; channelId: string }
  | { status: "deep_link"; channelId: string; deepLink: string }
  | { status: "pending_provider"; channelId: string }
  | { status: "error"; reason: string };

export async function createChannel(
  kind: ChannelKind,
  target: string,
): Promise<CreateChannelResult> {
  const response = await api("POST", "/v1/notification-channels", {
    kind,
    target,
  });
  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as {
      reasonCode?: string;
    };
    return { status: "error", reason: body.reasonCode ?? "failed" };
  }
  const body = (await response.json()) as {
    channelId: string;
    verify: string;
    deepLink?: string;
  };
  if (body.verify === "deep_link" && body.deepLink) {
    return { status: "deep_link", channelId: body.channelId, deepLink: body.deepLink };
  }
  if (body.verify === "code_sent") {
    return { status: "code_sent", channelId: body.channelId };
  }
  return { status: "pending_provider", channelId: body.channelId };
}

export async function verifyEmailCode(
  channelId: string,
  code: string,
): Promise<boolean> {
  const response = await api("POST", "/v1/notification-channels/verify", {
    channelId,
    code,
  });
  return response.ok;
}

export async function deleteChannel(channelId: string): Promise<boolean> {
  const response = await api(
    "DELETE",
    `/v1/notification-channels/${channelId}`,
  );
  return response.status === 204;
}
