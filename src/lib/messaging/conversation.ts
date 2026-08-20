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
  addMlsMembers,
  createMlsGroup,
  joinMlsWelcome,
  openMlsApplication,
  processMlsCommit,
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

interface GroupRecord {
  groupId: string;
  // The commit position this device's group state already covers:
  // the genesis commit for the creator, the Welcome's commit for a
  // joiner, then advanced as later commits are processed.
  processedPosition: string;
}

type GroupMap = Record<string, string | GroupRecord>;

function asRecord(
  stored: string | GroupRecord | undefined,
): GroupRecord | null {
  if (!stored) return null;
  // Legacy entries stored the bare hex group id; they predate follower
  // commits, so position 1 (the genesis commit) is covered.
  if (typeof stored === "string") {
    return { groupId: stored, processedPosition: "1" };
  }
  return stored;
}

async function groupRecordFor(
  conversationId: string,
): Promise<GroupRecord | null> {
  const map = (await idbGet<GroupMap>(GROUP_MAP_KEY)) ?? {};
  return asRecord(map[conversationId]);
}

async function groupIdFor(conversationId: string): Promise<Uint8Array | null> {
  const record = await groupRecordFor(conversationId);
  return record ? fromHex(record.groupId) : null;
}

async function rememberGroup(
  conversationId: string,
  groupId: Uint8Array,
  processedPosition: string,
): Promise<void> {
  const map = (await idbGet<GroupMap>(GROUP_MAP_KEY)) ?? {};
  map[conversationId] = { groupId: hex(groupId), processedPosition };
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
  return activatePlannedConversation(planned);
}

/**
 * Owner-side accept: the accepting owner is the MLS group creator and the
 * waiting customer is the welcome target. Same activation as a customer
 * start — only the plan source differs (the queued request, not a fresh
 * claim). Returns the conversation id.
 */
export async function acceptConversationRequest(
  requestId: string,
): Promise<string> {
  const planned = await api("POST", "/v1/conversation-requests/accept", {
    requestId,
  });
  return activatePlannedConversation(planned);
}

// Build the MLS group on this device from a returned plan and activate it
// with the real Commit + Welcome. Roster-shape agnostic: whoever this
// device is appears as the creator, and every 'welcome' member is added.
async function activatePlannedConversation(
  planned: Response,
): Promise<string> {
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
  if (
    welcomeTargets.length === 0 ||
    welcomeTargets.some((member) => !member.keyPackage)
  ) {
    throw new Error("unsupported_roster_shape");
  }

  const groupId = crypto.getRandomValues(new Uint8Array(32));
  await createMlsGroup(groupId);
  // One Add Commit covers every welcome target; the single Welcome
  // serves them all.
  const added = await addMlsMembers(
    groupId,
    welcomeTargets.map((member) => fromB64url(member.keyPackage!)),
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
        welcomeByInstallation: welcomeTargets.map((member) => ({
          installationId: member.installationId,
          welcome: b64url(added.welcome),
          welcomeSha256: b64url(welcomeSha),
        })),
      },
    },
    { "If-Match": `"plan-${plan.planId}-1"` },
  );
  if (activated.status !== 201) {
    throw new Error(await reason(activated, "activation_refused"));
  }
  await rememberGroup(plan.conversationId, groupId, "1");
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
    welcomes: {
      conversationId: string;
      welcome: string;
      commitPosition: string;
    }[];
  };
  for (const entry of body.welcomes) {
    if ((await groupIdFor(entry.conversationId)) !== null) continue;
    const groupId = await joinMlsWelcome(fromB64url(entry.welcome));
    // The Welcome's group state already covers its commit.
    await rememberGroup(entry.conversationId, groupId, entry.commitPosition);
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
  const record = await groupRecordFor(conversationId);
  const cache = await readMessageCache(conversationId);
  if (!record) return cache;
  const groupId = fromHex(record.groupId);
  const session = getSession();
  const fetchEnvelope = async (
    envelopeId: string,
  ): Promise<{
    envelope: string;
    sender: { installationId: string | null };
  } | null> => {
    const response = await api(
      "GET",
      `/v1/conversations/${conversationId}/envelopes/${envelopeId}`,
    );
    if (!response.ok) return null;
    return (await response.json()) as {
      envelope: string;
      sender: { installationId: string | null };
    };
  };
  // Events arrive in position order; commits MUST merge before any
  // later application message can decrypt.
  for (const event of events) {
    if (event.envelopeClass === "mls_commit") {
      if (BigInt(event.position) <= BigInt(record.processedPosition)) continue;
      const body = await fetchEnvelope(event.envelopeId);
      if (!body) return cache;
      if (body.sender.installationId !== session.installationId) {
        try {
          await processMlsCommit(groupId, fromB64url(body.envelope));
        } catch {
          // A commit this device cannot merge means every later
          // ciphertext is unreadable: stop here rather than mis-render.
          return cache;
        }
      }
      record.processedPosition = event.position;
      await rememberGroup(conversationId, groupId, event.position);
      continue;
    }
    if (event.envelopeClass !== "application") continue;
    if (cache[event.envelopeId]) continue;
    const body = await fetchEnvelope(event.envelopeId);
    if (!body) continue;
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
