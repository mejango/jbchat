"use client";

import { Fragment, useCallback, useEffect, useRef, useState } from "react";
import { useAccount, useSignMessage } from "wagmi";
import { MessagingProviders } from "@/providers/MessagingProviders";
import {
  api,
  enrollDevice,
  restoreSession,
  sessionEnded,
  type EnrollmentProgress,
} from "@/lib/messaging/client";
import {
  acceptConversationRequest,
  canDecrypt,
  conversationDetail,
  decryptedMessages,
  sendMessage,
  syncWelcomes,
  type CachedMessage,
} from "@/lib/messaging/conversation";
import { NotificationsButton } from "./NotificationsPanel";
import { DevicesButton } from "./DevicesPanel";
import { RelayButton } from "./RelayPanel";
import { truncateAddress } from "@/lib/messaging/identity";
import {
  Avatar,
  WalletMenu,
  useMessagingSession,
  useMounted,
  useViewAs,
} from "./WalletMenu";

interface ConversationSummary {
  conversationId: string;
  state: string;
  deliveryPurpose: string;
  role: string;
  lastPosition: string;
  lastActivityAt: string;
  project: { chainId: string; projectId: string };
}

interface ConversationEvent {
  position: string;
  envelopeId: string;
  envelopeClass: string;
  contentType: string;
  envelopeBytes: string;
  receivedAt?: string;
}

function dayLabel(iso: string): string {
  const date = new Date(iso);
  const today = new Date();
  const yesterday = new Date(today);
  yesterday.setDate(today.getDate() - 1);
  const sameDay = (a: Date, b: Date) =>
    a.getFullYear() === b.getFullYear() &&
    a.getMonth() === b.getMonth() &&
    a.getDate() === b.getDate();
  if (sameDay(date, today)) return "Today";
  if (sameDay(date, yesterday)) return "Yesterday";
  return date.toLocaleDateString(undefined, {
    month: "long",
    day: "numeric",
    year:
      date.getFullYear() === today.getFullYear() ? undefined : "numeric",
  });
}

function timeLabel(iso: string): string {
  return new Date(iso).toLocaleTimeString(undefined, {
    hour: "numeric",
    minute: "2-digit",
  });
}

function relativeTime(iso: string): string {
  const ms = Date.now() - Date.parse(iso);
  if (!Number.isFinite(ms) || ms < 0) return "";
  const minutes = Math.floor(ms / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return days < 7 ? `${days}d ago` : new Date(iso).toLocaleDateString();
}

// Last position the user has SEEN per conversation, kept locally — the
// server never learns read state. Unread = lastPosition beyond this.
const SEEN_KEY = "jbm.seenPositions";
function seenPositions(): Record<string, number> {
  try {
    return JSON.parse(window.localStorage.getItem(SEEN_KEY) ?? "{}");
  } catch {
    return {};
  }
}
function markSeen(conversationId: string, position: string): void {
  const seen = seenPositions();
  seen[conversationId] = Math.max(seen[conversationId] ?? 0, Number(position));
  window.localStorage.setItem(SEEN_KEY, JSON.stringify(seen));
}

export function MessagingApp() {
  return (
    <MessagingProviders>
      <div className="mxApp">
        <header className="mxHeader">
          <div className="mxRow">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src="/juicebox-mark.svg" alt="" width={25} height={32} />
            <div>
              <div className="mxDisplay" style={{ fontSize: 16 }}>
                Fruitful
              </div>
              <div className="mxHint">Chat for Juicebox</div>
            </div>
          </div>
          <WalletMenu />
        </header>
        <main className="mxShell">
          <Body />
        </main>
      </div>
    </MessagingProviders>
  );
}

function Body() {
  const mounted = useMounted();
  const viewAs = useViewAs();
  const session = useMessagingSession();
  const { isConnected } = useAccount();

  useEffect(() => {
    void restoreSession();
  }, []);
  if (!mounted) return null;

  if (viewAs) {
    return (
      <section className="mxCard" style={{ padding: "1.5rem" }}>
        <div className="mxRow">
          <Avatar address={viewAs} size={48} />
          <div>
            <h1 className="mxDisplay" style={{ margin: 0, fontSize: 20 }}>
              Viewing {truncateAddress(viewAs)}
            </h1>
            <p className="mxHint" style={{ margin: 0 }}>
              Public account view. Conversations, devices, and message
              content are end-to-end private and never visible here.
            </p>
          </div>
        </div>
      </section>
    );
  }

  if (!isConnected) {
    return (
      <section className="mxCard" style={{ padding: "2rem", maxWidth: 560 }}>
        <h1 className="mxDisplay" style={{ marginTop: 0, fontSize: 22 }}>
          Support chats for your on-chain purchases
        </h1>
        <p style={{ color: "var(--mx-smoke-700)" }}>
          Pay a Juicebox project, then talk to its team privately - shipping
          details and support threads live here, encrypted to your devices,
          never on-chain.
        </p>
        <p className="mxHint">
          Sign in with your wallet to secure this device and open your inbox.
        </p>
      </section>
    );
  }

  if (session.status !== "ready") {
    return <EnrollPanel />;
  }
  return <Inbox />;
}

function EnrollPanel() {
  const { address, chainId } = useAccount();
  const { signMessageAsync } = useSignMessage();
  const [step, setStep] = useState<EnrollmentProgress | "idle" | "error">(
    "idle",
  );
  const [reason, setReason] = useState<string | null>(null);

  const start = useCallback(async () => {
    if (!address || !chainId) return;
    setReason(null);
    try {
      await enrollDevice({
        walletAddress: address,
        chainId,
        signMessage: (message) => signMessageAsync({ message }),
        onProgress: setStep,
      });
    } catch (error) {
      setStep("error");
      setReason(error instanceof Error ? error.message : "enrollment_failed");
    }
  }, [address, chainId, signMessageAsync]);

  const stepCopy: Record<string, string> = {
    allocating: "Reserving your enrollment…",
    "generating-keys": "Generating device keys in this browser…",
    "awaiting-wallet-signature": "Confirm the sign-in message in your wallet…",
    verifying: "Verifying your wallet against finalized chain state…",
  };

  return (
    <section className="mxCard" style={{ padding: "2rem", maxWidth: 560 }}>
      <h1 className="mxDisplay" style={{ marginTop: 0, fontSize: 22 }}>
        Secure this device
      </h1>
      {sessionEnded() === "expired" ? (
        <p style={{ color: "var(--mx-melon)", marginTop: 0 }}>
          Your session expired — enroll again to keep chatting. Your
          conversations are safe.
        </p>
      ) : null}
      <p style={{ color: "var(--mx-smoke-700)" }}>
        Enrollment creates non-exportable keys in this browser and proves
        wallet control with a one-time signature. The service verifies your
        wallet against finalized chain state through an independent RPC
        quorum before issuing a device credential.
      </p>
      {step === "idle" || step === "error" || step === "done" ? (
        <button className="mxBtnPrimary" onClick={start}>
          Enroll this device
        </button>
      ) : (
        <p className="mxHint">{stepCopy[step] ?? "Working…"}</p>
      )}
      {step === "error" ? (
        <p className="mxError" style={{ marginTop: 8 }}>
          {reason === "enrollment_verification_unavailable"
            ? "Chain verification is unavailable for this wallet\u2019s network right now. Smart-contract wallets aren\u2019t supported yet; a regular or 7702-delegated EOA works."
            : reason === "browser_missing_ed25519"
              ? "This browser cannot generate Ed25519 keys. Use a current Chrome, Edge, or Safari."
              : `Enrollment was refused (${reason}).`}
        </p>
      ) : null}
    </section>
  );
}

function Inbox() {
  const [conversations, setConversations] = useState<
    ConversationSummary[] | null
  >(null);
  const [selected, setSelected] = useState<ConversationSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [meta, setMeta] = useState<
    Record<string, { name: string | null; logoUri: string | null }>
  >({});
  const metaFetched = useRef(new Set<string>());

  const reload = useCallback(async () => {
    await syncWelcomes().catch(() => undefined);
    const response = await api("GET", "/v1/conversations");
    if (!response.ok) {
      setError("Your inbox could not be loaded.");
      return;
    }
    const body = (await response.json()) as {
      conversations: ConversationSummary[];
    };
    setConversations(body.conversations);
    setError(null);
    // Resolve project names/logos for any rows we have not looked up yet.
    const keys = body.conversations
      .map(
        (conversation) =>
          `${projectKey(conversation.project.chainId)}:${conversation.project.projectId}`,
      )
      .filter((key) => !metaFetched.current.has(key));
    if (keys.length > 0) {
      keys.forEach((key) => metaFetched.current.add(key));
      void fetch(`/api/juicebox/project-meta?keys=${keys.join(",")}`)
        .then((res) => (res.ok ? res.json() : {}))
        .then((body: Record<string, { name: string | null; logoUri: string | null }>) =>
          setMeta((current) => ({ ...current, ...body })),
        )
        .catch(() => undefined);
    }
  }, []);

  useEffect(() => {
    // Poll so an accepted chat appears for the waiting customer (the
    // welcome sync inside reload() joins the MLS group) without a refresh.
    const timer = setTimeout(() => void reload(), 0);
    const interval = setInterval(() => void reload(), 20000);
    return () => {
      clearTimeout(timer);
      clearInterval(interval);
    };
  }, [reload]);

  if (selected) {
    const selectedMeta =
      meta[
        `${projectKey(selected.project.chainId)}:${selected.project.projectId}`
      ];
    return (
      <ConversationView
        conversation={selected}
        projectName={selectedMeta?.name ?? null}
        onBack={() => {
          setSelected(null);
          void reload();
        }}
      />
    );
  }

  return (
    <div style={{ display: "grid", gap: 16 }}>
      <div className="mxRow" style={{ justifyContent: "space-between" }}>
        <h1 className="mxDisplay" style={{ margin: 0, fontSize: 20 }}>
          Messages
        </h1>
        <div className="mxRow">
          <DevicesButton />
          <NotificationsButton />
        </div>
      </div>
      {error ? <p className="mxError">{error}</p> : null}

      <Discovery />

      <RequestsQueue onAccepted={reload} />

      {conversations === null ? (
        <p className="mxHint">Loading your inbox…</p>
      ) : conversations.length === 0 ? (
        <section className="mxCard" style={{ padding: "1.5rem" }}>
          <h2 className="mxDisplay" style={{ marginTop: 0, fontSize: 17 }}>
            No open chats yet
          </h2>
          <p style={{ color: "var(--mx-smoke-700)" }}>
            Start one from a project you&apos;ve paid or own above.
          </p>
        </section>
      ) : (
        conversations.map((conversation) => {
          const key = projectKey(conversation.project.chainId);
          const info = meta[`${key}:${conversation.project.projectId}`];
          const unread =
            Number(conversation.lastPosition) >
            (seenPositions()[conversation.conversationId] ?? 0);
          return (
            <button
              key={conversation.conversationId}
              className="mxCard mxRow"
              style={{
                padding: "1rem",
                cursor: "pointer",
                font: "inherit",
                textAlign: "left",
                width: "100%",
              }}
              onClick={() => setSelected(conversation)}
            >
              {info?.logoUri ? (
                // eslint-disable-next-line @next/next/no-img-element
                <img
                  src={info.logoUri}
                  alt=""
                  style={{
                    width: 40,
                    height: 40,
                    borderRadius: 8,
                    objectFit: "cover",
                  }}
                />
              ) : (
                <Avatar address={conversation.conversationId} size={40} />
              )}
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: unread ? 700 : 500 }}>
                  {info?.name ?? `Project #${conversation.project.projectId}`}
                </div>
                <div className="mxHint">
                  {CHAIN_LABEL[conversation.project.chainId] ??
                    conversation.project.chainId}{" "}
                  · {conversation.role === "customer" ? "support" : "customer chat"}
                  {conversation.lastActivityAt
                    ? ` · ${relativeTime(conversation.lastActivityAt)}`
                    : ""}
                </div>
              </div>
              {unread ? (
                <span
                  className="mxChip"
                  style={{
                    background: "var(--mx-melon)",
                    color: "#fff",
                  }}
                >
                  New
                </span>
              ) : null}
            </button>
          );
        })
      )}
    </div>
  );
}

// "eip155:8453" -> "8453", for project-meta keys.
function projectKey(chainId: string): string {
  return chainId.replace(/^eip155:/, "");
}


interface OwnerRequest {
  requestId: string;
  chainId: string;
  projectId: string;
  requesterAccountId: string;
  requesterWallet: string | null;
  createdAt: string;
}

const CHAIN_LABEL: Record<string, string> = {
  "eip155:1": "Ethereum",
  "eip155:10": "Optimism",
  "eip155:8453": "Base",
  "eip155:42161": "Arbitrum",
};

function RequestsQueue({ onAccepted }: { onAccepted: () => void }) {
  const [requests, setRequests] = useState<OwnerRequest[] | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let live = true;
    const load = () =>
      void api("GET", "/v1/conversation-requests")
        .then((response) => (response.ok ? response.json() : null))
        .then((body) => {
          if (live && body) setRequests(body.requests ?? []);
        })
        .catch(() => undefined);
    const kickoff = setTimeout(load, 0);
    const interval = setInterval(load, 20000);
    return () => {
      live = false;
      clearTimeout(kickoff);
      clearInterval(interval);
    };
  }, [reloadKey]);

  if (!requests || requests.length === 0) return null;

  return (
    <section style={{ display: "grid", gap: 8 }}>
      <h2 className="mxDisplay" style={{ margin: 0, fontSize: 15 }}>
        Requests to attend — customers waiting to reach you
      </h2>
      {requests.map((request) => (
        <RequestRow
          key={request.requestId}
          request={request}
          onAccepted={() => {
            setReloadKey((key) => key + 1);
            onAccepted();
          }}
        />
      ))}
    </section>
  );
}

function RequestRow({
  request,
  onAccepted,
}: {
  request: OwnerRequest;
  onAccepted: () => void;
}) {
  const [state, setState] = useState<
    "idle" | "working" | "declining" | "error"
  >("idle");

  const accept = async () => {
    setState("working");
    try {
      // Owner-side: build the MLS group on this device and welcome the
      // waiting customer, using their published KeyPackage.
      await acceptConversationRequest(request.requestId);
      onAccepted();
    } catch {
      setState("error");
    }
  };

  const decline = async () => {
    setState("declining");
    const response = await api("POST", "/v1/conversation-requests/decline", {
      requestId: request.requestId,
    }).catch(() => null);
    if (response?.ok) onAccepted();
    else setState("error");
  };

  return (
    <div className="mxCard mxRow" style={{ padding: "0.9rem 1rem" }}>
      <Avatar address={request.requesterAccountId} size={40} />
      <div style={{ flex: 1 }}>
        <div style={{ fontWeight: 500 }}>
          Project #{request.projectId} ·{" "}
          {CHAIN_LABEL[request.chainId] ?? request.chainId}
        </div>
        <div className="mxHint">
          {request.requesterWallet
            ? `${truncateAddress(request.requesterWallet.split(":")[2] ?? request.requesterWallet)} — a paid customer — wants to start a chat.`
            : "A paid customer wants to start a chat."}{" "}
          {relativeTime(request.createdAt)}
        </div>
      </div>
      <button
        className="mxBtnSecondary"
        disabled={state === "working" || state === "declining"}
        onClick={() => void decline()}
      >
        {state === "declining" ? "Declining…" : "Decline"}
      </button>
      <button
        className="mxBtnPrimary"
        disabled={state === "working" || state === "declining"}
        onClick={() => void accept()}
      >
        {state === "working"
          ? "Opening…"
          : state === "error"
            ? "Try again"
            : "Accept"}
      </button>
    </div>
  );
}

interface DiscoveredProject {
  chainId: number;
  projectId: number;
  name: string | null;
  logoUri: string | null;
  isRevnet: boolean;
}
interface CustomerProject extends DiscoveredProject {
  volume: string;
  paymentsCount: number;
  latestPayment: { txHash: string; logIndex: number } | null;
}
interface OwnerProject extends DiscoveredProject {
  payerCount: number;
}

const CHAIN_NAME: Record<number, string> = {
  1: "Ethereum",
  10: "Optimism",
  8453: "Base",
  42161: "Arbitrum",
};

function ProjectRow({
  project,
  meta,
  action,
}: {
  project: DiscoveredProject;
  meta: string;
  action: string;
}) {
  return (
    <div className="mxCard mxRow" style={{ padding: "0.9rem 1rem" }}>
      {project.logoUri ? (
        // eslint-disable-next-line @next/next/no-img-element
        <img
          src={project.logoUri}
          alt=""
          style={{ width: 40, height: 40, borderRadius: 8, objectFit: "cover" }}
        />
      ) : (
        <Avatar address={`${project.chainId}:${project.projectId}`} size={40} />
      )}
      <div style={{ flex: 1 }}>
        <div style={{ fontWeight: 500 }}>
          {project.name ?? `Project #${project.projectId}`}
        </div>
        <div className="mxHint">
          {CHAIN_NAME[project.chainId] ?? `Chain ${project.chainId}`} · {meta}
        </div>
      </div>
      <span className="mxChip">{action}</span>
    </div>
  );
}

const V6_TERMINAL = "0x130f5dd2bd8805443cf41755253d778a75a67f53";

function CustomerCard({ project }: { project: CustomerProject }) {
  const { address } = useAccount();
  const [state, setState] = useState<
    "idle" | "working" | "requested" | "opened" | "error"
  >("idle");

  const start = async () => {
    if (!address || !project.latestPayment) {
      setState("error");
      return;
    }
    setState("working");
    try {
      const claim = await api("POST", "/v1/eligibility/purchase-claims", {
        chainId: project.chainId,
        projectId: project.projectId,
        walletRef: `eip155:${project.chainId}:${address.toLowerCase()}`,
        transactionHash: project.latestPayment.txHash,
        payLogIndex: project.latestPayment.logIndex,
        terminal: V6_TERMINAL,
      });
      if (claim.status !== 201) {
        setState("error");
        return;
      }
      const { claimHandle } = (await claim.json()) as { claimHandle: string };
      const requested = await api("POST", "/v1/conversation-requests", {
        eligibilityClaimHandle: claimHandle,
        walletRef: `eip155:${project.chainId}:${address.toLowerCase()}`,
      });
      setState(requested.ok ? "requested" : "error");
    } catch {
      setState("error");
    }
  };

  const label =
    state === "working"
      ? "Requesting…"
      : state === "requested"
        ? "Requested ✓"
        : state === "error"
          ? "Try again"
          : project.latestPayment
            ? "Open support"
            : "No payment found";

  return (
    <button
      className="mxCard mxRow"
      style={{
        padding: "0.9rem 1rem",
        cursor: project.latestPayment ? "pointer" : "default",
        font: "inherit",
        textAlign: "left",
        width: "100%",
      }}
      disabled={state === "working" || state === "requested" || !project.latestPayment}
      onClick={() => void start()}
    >
      {project.logoUri ? (
        // eslint-disable-next-line @next/next/no-img-element
        <img
          src={project.logoUri}
          alt=""
          style={{ width: 40, height: 40, borderRadius: 8, objectFit: "cover" }}
        />
      ) : (
        <Avatar address={`${project.chainId}:${project.projectId}`} size={40} />
      )}
      <div style={{ flex: 1 }}>
        <div style={{ fontWeight: 500 }}>
          {project.name ?? `Project #${project.projectId}`}
        </div>
        <div className="mxHint">
          {CHAIN_NAME[project.chainId] ?? `Chain ${project.chainId}`} ·{" "}
          {project.paymentsCount} payment
          {project.paymentsCount === 1 ? "" : "s"}
        </div>
      </div>
      <span className="mxChip">{label}</span>
    </button>
  );
}

function Discovery() {
  const { address } = useAccount();
  const [data, setData] = useState<{
    asCustomer: CustomerProject[];
    asOwner: OwnerProject[];
  } | null>(null);
  // Owned projects auto-register this device as support staff (the server
  // re-proves ownership on-chain), so the owner sees incoming requests and
  // can accept without any manual step. Once per project per page load.
  const staffAttempted = useRef(new Set<string>());

  useEffect(() => {
    if (!data) return;
    for (const project of data.asOwner) {
      const key = `${project.chainId}:${project.projectId}`;
      if (staffAttempted.current.has(key)) continue;
      staffAttempted.current.add(key);
      void api("POST", "/v1/staff-registrations", {
        chainId: project.chainId,
        projectId: project.projectId,
      }).catch(() => staffAttempted.current.delete(key));
    }
  }, [data]);

  useEffect(() => {
    if (!address) return;
    let live = true;
    const load = () =>
      void fetch(`/api/juicebox/discovery?address=${address}`, {
        cache: "no-store",
      })
        .then((response) => (response.ok ? response.json() : null))
        .then((body) => {
          if (live && body) setData(body);
        })
        .catch(() => undefined);
    const kickoff = setTimeout(load, 0);
    // Re-poll so a fresh payment shows up once bendystraw indexes it,
    // without a manual refresh.
    const interval = setInterval(load, 20000);
    return () => {
      live = false;
      clearTimeout(kickoff);
      clearInterval(interval);
    };
  }, [address]);

  if (!data || (data.asCustomer.length === 0 && data.asOwner.length === 0)) {
    return null;
  }

  return (
    <div style={{ display: "grid", gap: 20 }}>
      {data.asCustomer.length > 0 ? (
        <section style={{ display: "grid", gap: 8 }}>
          <h2 className="mxDisplay" style={{ margin: 0, fontSize: 15 }}>
            Start a chat — projects you&apos;ve paid
          </h2>
          {data.asCustomer.map((project) => (
            <CustomerCard
              key={`c-${project.chainId}-${project.projectId}`}
              project={project}
            />
          ))}
        </section>
      ) : null}

      {data.asOwner.length > 0 ? (
        <section style={{ display: "grid", gap: 8 }}>
          <h2 className="mxDisplay" style={{ margin: 0, fontSize: 15 }}>
            Your projects — customers who can reach you
          </h2>
          {data.asOwner.map((project) => (
            <ProjectRow
              key={`o-${project.chainId}-${project.projectId}`}
              project={project}
              meta={`${project.payerCount} payer${project.payerCount === 1 ? "" : "s"}`}
              action="Owner"
            />
          ))}
        </section>
      ) : null}
    </div>
  );
}

function ConversationView({
  conversation,
  projectName,
  onBack,
}: {
  conversation: ConversationSummary;
  projectName: string | null;
  onBack: () => void;
}) {
  const [events, setEvents] = useState<ConversationEvent[] | null>(null);
  const [messages, setMessages] = useState<Record<string, CachedMessage>>({});
  const [decryptable, setDecryptable] = useState(false);
  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [relaySeats, setRelaySeats] = useState<
    { installationId: string; role: string; mine: boolean }[]
  >([]);

  const refresh = useCallback(async () => {
    const response = await api(
      "GET",
      `/v1/conversations/${conversation.conversationId}/events`,
    );
    if (!response.ok) {
      setError("This conversation’s transcript could not be loaded.");
      return;
    }
    const body = (await response.json()) as { events: ConversationEvent[] };
    setEvents(body.events);
    if (body.events.length > 0) {
      markSeen(
        conversation.conversationId,
        body.events[body.events.length - 1].position,
      );
    }
    setDecryptable(await canDecrypt(conversation.conversationId));
    try {
      setRelaySeats((await conversationDetail(conversation.conversationId)).relay?.seats ?? []);
    } catch {
      // The transcript stays useful without the roster banner.
    }
    const decrypted = await decryptedMessages(
      conversation.conversationId,
      body.events,
    );
    setMessages(decrypted);
    setError(null);
  }, [conversation.conversationId]);

  useEffect(() => {
    const kickoff = setTimeout(() => void refresh(), 0);
    const timer = setInterval(() => void refresh(), 5000);
    return () => {
      clearTimeout(kickoff);
      clearInterval(timer);
    };
  }, [refresh]);

  const submit = useCallback(async () => {
    const text = draft.trim();
    if (!text || sending) return;
    setSending(true);
    try {
      await sendMessage(conversation.conversationId, text);
      setDraft("");
      await refresh();
    } catch (sendError) {
      setError(
        sendError instanceof Error && sendError.message === "policy_head_unwitnessed"
          ? "The channel is still being co-signed by the transparency witness. Try again in a moment."
          : "Your message could not be sent. Try again.",
      );
    } finally {
      setSending(false);
    }
  }, [conversation.conversationId, draft, refresh, sending]);

  return (
    <div style={{ display: "grid", gap: 16 }}>
      <div className="mxRow">
        <button className="mxBtnSecondary" onClick={onBack}>
          ← Inbox
        </button>
        <h1 className="mxDisplay" style={{ margin: 0, fontSize: 18 }}>
          {projectName ?? `Project #${conversation.project.projectId}`}
          {conversation.role === "customer" ? " support" : ""}
        </h1>
        {decryptable ? (
          <RelayButton conversationId={conversation.conversationId} />
        ) : null}
      </div>
      {relaySeats.filter((seat) => !seat.mine).map((seat) => (
        <p key={seat.installationId} className="mxHint" style={{ margin: 0 }}>
          {seat.role === "customer" ? "The customer’s" : "The project’s"}{" "}
          Telegram relay can read this conversation.
        </p>
      ))}
      <section
        className="mxCard"
        style={{ padding: "1.25rem", display: "grid", gap: 8 }}
      >
        {error ? <p className="mxError">{error}</p> : null}
        {events === null ? (
          <p className="mxHint">Loading transcript…</p>
        ) : (
          <ol style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 8 }}>
            {events.map((event, index) => {
              const previous = index > 0 ? events[index - 1] : null;
              const separator =
                event.receivedAt &&
                (!previous?.receivedAt ||
                  dayLabel(previous.receivedAt) !== dayLabel(event.receivedAt)) ? (
                  <li
                    key={`day-${event.position}`}
                    className="mxHint"
                    style={{ textAlign: "center", padding: "0.25rem 0" }}
                  >
                    {dayLabel(event.receivedAt)}
                  </li>
                ) : null;
              if (event.envelopeClass !== "application") {
                return (
                  <Fragment key={event.position}>
                    {separator}
                    <li className="mxHint" style={{ textAlign: "center" }}>
                      {event.position === "1"
                        ? "Chat opened — end-to-end encrypted"
                        : "Membership updated"}
                    </li>
                  </Fragment>
                );
              }
              const message = messages[event.envelopeId];
              const mine = message?.mine ?? false;
              return (
                <Fragment key={event.position}>
                  {separator}
                  <li
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      alignItems: mine ? "flex-end" : "flex-start",
                    }}
                  >
                    <span
                      title={
                        event.receivedAt
                          ? new Date(event.receivedAt).toLocaleString()
                          : undefined
                      }
                      style={{
                        maxWidth: "75%",
                        padding: "0.5rem 0.75rem",
                        borderRadius: 12,
                        background: mine ? "var(--mx-bluebs)" : "var(--mx-smoke-100)",
                        color: mine ? "white" : "inherit",
                        whiteSpace: "pre-wrap",
                        overflowWrap: "anywhere",
                      }}
                    >
                      {message && message.text !== ""
                        ? message.text
                        : decryptable
                          ? "Encrypted message"
                          : "Encrypted on another device"}
                    </span>
                    {event.receivedAt ? (
                      <span
                        className="mxHint"
                        style={{ fontSize: 11, padding: "0.1rem 0.25rem" }}
                      >
                        {timeLabel(event.receivedAt)}
                      </span>
                    ) : null}
                  </li>
                </Fragment>
              );
            })}
          </ol>
        )}
      </section>
      {decryptable ? (
        <form
          className="mxRow"
          onSubmit={(event) => {
            event.preventDefault();
            void submit();
          }}
        >
          <input
            className="mxInput"
            style={{ flex: 1 }}
            placeholder="Write a message…"
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
          />
          <button className="mxBtnPrimary" type="submit" disabled={sending || !draft.trim()}>
            {sending ? "Sending…" : "Send"}
          </button>
        </form>
      ) : (
        <p className="mxHint">
          This conversation’s keys live on the device that opened it.
          Messages decrypt and send only there.
        </p>
      )}
    </div>
  );
}
