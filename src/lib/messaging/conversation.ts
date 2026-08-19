"use client";

/**
 * Conversation operations: MLS group lifecycle bound to the delivery
 * API. The conversation-to-group-id map and the decrypted-message cache
 * live in IndexedDB - MLS decrypts each ciphertext exactly once (the
 * ratchet retires keys), so every opened message is cached before the
 * plaintext is shown.
 */

import { api, getSession } from "./client";
import { idbGet, idbSet } from "./idb";
import {
  addMlsMember,
  createMlsGroup,
  joinMlsWelcome,
  openMlsApplication,
  sealMlsApplication,
} from "./mls";

const GROUP_MAP_KEY = "mls-group-map-v1";
const MESSAGE_CACHE_PREFIX = "mls-messages-v1:";

const APPLICATION_CONTENT_TYPE =
  "application/vnd.juicebox.messaging.mls-private-message";

function b64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function fromB64url(value: string): Uint8Array {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function fromHex(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

type GroupMap = Record<string, string>;

async function groupIdFor(conversationId: string): Promise<Uint8Array | null> {
  const map = (await idbGet<GroupMap>(GROUP_MAP_KEY)) ?? {};
  const stored = map[conversationId];
  return stored ? fromHex(stored) : null;
}

async function rememberGroup(
  conversationId: string,
  groupId: Uint8Array,
): Promise<void> {
  const map = (await idbGet<GroupMap>(GROUP_MAP_KEY)) ?? {};
  map[conversationId] = hex(groupId);
  await idbSet(GROUP_MAP_KEY, map);
}

export interface CachedMessage {
  readonly text: string;
  readonly mine: boolean;
  readonly position: string;
}

type MessageCache = Record<string, CachedMessage>;

async function readMessageCache(conversationId: string): Promise<MessageCache> {
  return (
    (await idbGet<MessageCache>(MESSAGE_CACHE_PREFIX + conversationId)) ?? {}
  );
}

async function writeMessageCache(
  conversationId: string,
  cache: MessageCache,
): Promise<void> {
  await idbSet(MESSAGE_CACHE_PREFIX + conversationId, cache);
}

interface PlanMember {
  installationId: string;
  bootstrapMode: string;
  keyPackage?: string;
}

interface ConversationDetail {
  etag: string;
  epoch: string;
  rosterVersion: string;
  confirmedTranscriptHash: string;
  lastPosition: string;
  state: string;
  policyHead: {
    policyHeadId: string;
    policyHeadSequence: string;
    policyHeadHash: string;
    witnessState: string;
  } | null;
}

async function reason(response: Response, fallback: string): Promise<string> {
  try {
    const body = (await response.json()) as { reasonCode?: string };
    return body.reasonCode ?? fallback;
  } catch {
    return fallback;
  }
}

/**
 * Turn an eligibility claim into an active, end-to-end encrypted
 * conversation: plan, build the MLS group on this device, and activate
 * with the real Commit + Welcome. Returns the conversation id.
 */
export async function startConversation(claimHandle: string): Promise<string> {
  const planned = await api("POST", "/v1/conversation-plans", {
    eligibilityClaimHandle: claimHandle,
  });
  if (planned.status === 200) {
    const body = (await planned.json()) as { conversationId: string };
    return body.conversationId;
  }
  if (planned.status !== 201) {
    throw new Error(await reason(planned, "plan_refused"));
  }
  const plan = (await planned.json()) as {
    planId: string;
    conversationId: string;
    rosterHash: string;
    externalSendersHash: string;
    roster: PlanMember[];
  };
  const welcomeTargets = plan.roster.filter(
    (member) => member.bootstrapMode === "welcome",
  );
  // ponytail: one Add Commit per activation; support conversations have a
  // single staff installation today. Multi-device staff needs a
  // multi-KeyPackage addMembers in the wasm core.
  if (welcomeTargets.length !== 1 || !welcomeTargets[0].keyPackage) {
    throw new Error("unsupported_roster_shape");
  }

  const groupId = crypto.getRandomValues(new Uint8Array(32));
  await createMlsGroup(groupId);
  const added = await addMlsMember(
    groupId,
    fromB64url(welcomeTargets[0].keyPackage),
  );
  const commit = added.commit;
  const commitSha = new Uint8Array(
    await crypto.subtle.digest("SHA-256", commit.slice().buffer),
  );
  const welcomeSha = new Uint8Array(
    await crypto.subtle.digest("SHA-256", added.welcome.slice().buffer),
  );

  const activated = await api(
    "POST",
    "/v1/conversations",
    {
      planId: plan.planId,
      conversationId: plan.conversationId,
      rosterHash: plan.rosterHash,
      externalSendersHash: plan.externalSendersHash,
      mls: {
        cipherSuite: "0x0001",
        groupId: b64url(groupId),
        epoch: String(added.epoch),
        envelopeId: crypto.randomUUID(),
        commit: b64url(commit),
        envelopeSha256: b64url(commitSha),
        resultingConfirmedTranscriptHash: b64url(added.confirmedTranscriptHash),
        welcomeByInstallation: [
          {
            installationId: welcomeTargets[0].installationId,
            welcome: b64url(added.welcome),
            welcomeSha256: b64url(welcomeSha),
          },
        ],
      },
    },
    { "If-Match": `"plan-${plan.planId}-1"` },
  );
  if (activated.status !== 201) {
    throw new Error(await reason(activated, "activation_refused"));
  }
  await rememberGroup(plan.conversationId, groupId);
  return plan.conversationId;
}

/**
 * Pull pending Welcomes for this installation and join their groups.
 * Idempotent: conversations already in the group map are skipped.
 */
export async function syncWelcomes(): Promise<void> {
  const session = getSession();
  if (session.status !== "ready" || !session.installationId) return;
  const response = await api(
    "GET",
    `/v1/installations/${session.installationId}/welcomes`,
  );
  if (!response.ok) return;
  const body = (await response.json()) as {
    welcomes: { conversationId: string; welcome: string }[];
  };
  for (const entry of body.welcomes) {
    if ((await groupIdFor(entry.conversationId)) !== null) continue;
    const groupId = await joinMlsWelcome(fromB64url(entry.welcome));
    await rememberGroup(entry.conversationId, groupId);
  }
}

export async function conversationDetail(
  conversationId: string,
): Promise<ConversationDetail> {
  const response = await api("GET", `/v1/conversations/${conversationId}`);
  if (!response.ok) {
    throw new Error(await reason(response, "conversation_unavailable"));
  }
  return (await response.json()) as ConversationDetail;
}

export async function canDecrypt(conversationId: string): Promise<boolean> {
  return (await groupIdFor(conversationId)) !== null;
}

/**
 * Decrypt every application envelope in the page that is not already in
 * the local cache. Own messages come from the send-time cache (MLS
 * cannot open its own ciphertext); peer messages decrypt exactly once
 * and are cached immediately.
 */
export async function decryptedMessages(
  conversationId: string,
  events: { envelopeId: string; envelopeClass: string; position: string }[],
): Promise<Record<string, CachedMessage>> {
  const groupId = await groupIdFor(conversationId);
  const cache = await readMessageCache(conversationId);
  if (!groupId) return cache;
  const session = getSession();
  for (const event of events) {
    if (event.envelopeClass !== "application") continue;
    if (cache[event.envelopeId]) continue;
    const response = await api(
      "GET",
      `/v1/conversations/${conversationId}/envelopes/${event.envelopeId}`,
    );
    if (!response.ok) continue;
    const body = (await response.json()) as {
      envelope: string;
      sender: { installationId: string | null };
    };
    if (body.sender.installationId === session.installationId) {
      // Own ciphertext without a send-time cache entry (e.g. cleared
      // storage): unrecoverable by design.
      cache[event.envelopeId] = {
        text: "",
        mine: true,
        position: event.position,
      };
      continue;
    }
    try {
      const plaintext = await openMlsApplication(
        groupId,
        fromB64url(body.envelope),
      );
      cache[event.envelopeId] = {
        text: new TextDecoder().decode(plaintext),
        mine: false,
        position: event.position,
      };
    } catch {
      cache[event.envelopeId] = {
        text: "",
        mine: false,
        position: event.position,
      };
    }
    await writeMessageCache(conversationId, cache);
  }
  return cache;
}

/** Seal and append one message; caches the plaintext under its envelope id. */
export async function sendMessage(
  conversationId: string,
  text: string,
): Promise<void> {
  const groupId = await groupIdFor(conversationId);
  if (!groupId) throw new Error("group_unavailable");
  const detail = await conversationDetail(conversationId);
  if (!detail.policyHead || detail.policyHead.witnessState !== "verified") {
    throw new Error("policy_head_unwitnessed");
  }
  const sealed = await sealMlsApplication(
    groupId,
    new TextEncoder().encode(text),
  );
  const envelopeSha = new Uint8Array(
    await crypto.subtle.digest("SHA-256", sealed.slice().buffer),
  );
  const envelopeId = crypto.randomUUID();
  const idempotencyKey = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const response = await api(
    "POST",
    `/v1/conversations/${conversationId}/envelopes`,
    {
      envelopeId,
      policyHeadId: detail.policyHead.policyHeadId,
      policyHeadSequence: detail.policyHead.policyHeadSequence,
      policyHeadHash: detail.policyHead.policyHeadHash,
      expectedEpoch: detail.epoch,
      expectedRosterVersion: detail.rosterVersion,
      expectedConfirmedTranscriptHash: detail.confirmedTranscriptHash,
      contentType: APPLICATION_CONTENT_TYPE,
      ciphertext: b64url(sealed),
      envelopeSha256: b64url(envelopeSha),
      attachmentIds: [],
    },
    {
      "If-Match": detail.etag,
      "Idempotency-Key": idempotencyKey,
    },
  );
  if (response.status !== 201) {
    throw new Error(await reason(response, "send_failed"));
  }
  const cache = await readMessageCache(conversationId);
  const accepted = (await response.json()) as {
    receipt?: { position?: string };
  };
  cache[envelopeId] = {
    text,
    mine: true,
    position: accepted.receipt?.position ?? detail.lastPosition,
  };
  await writeMessageCache(conversationId, cache);
}
