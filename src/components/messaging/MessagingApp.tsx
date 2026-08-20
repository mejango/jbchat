"use client";

import { useCallback, useEffect, useState } from "react";
import { useAccount, useSignMessage } from "wagmi";
import { MessagingProviders } from "@/providers/MessagingProviders";
import {
  api,
  enrollDevice,
  restoreSession,
  type EnrollmentProgress,
} from "@/lib/messaging/client";
import {
  canDecrypt,
  decryptedMessages,
  sendMessage,
  startConversation,
  syncWelcomes,
  type CachedMessage,
} from "@/lib/messaging/conversation";
import {
  disablePush,
  enablePush,
  pushState,
  type PushState,
} from "@/lib/messaging/push";
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
  const [claimOpen, setClaimOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => void reload(), 0);
    return () => clearTimeout(timer);
  }, [reload]);

  if (selected) {
    return (
      <ConversationView
        conversation={selected}
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
          <PushToggle />
          <button className="mxBtnSecondary" onClick={() => setClaimOpen(true)}>
            Claim a purchase
          </button>
        </div>
      </div>
      {error ? <p className="mxError">{error}</p> : null}

      <Discovery onStart={() => setClaimOpen(true)} />

      {conversations === null ? (
        <p className="mxHint">Loading your inbox…</p>
      ) : conversations.length === 0 ? (
        <section className="mxCard" style={{ padding: "1.5rem" }}>
          <h2 className="mxDisplay" style={{ marginTop: 0, fontSize: 17 }}>
            No open chats yet
          </h2>
          <p style={{ color: "var(--mx-smoke-700)" }}>
            Start one from a project you&apos;ve paid or own above, or claim a
            purchase receipt directly.
          </p>
        </section>
      ) : (
        conversations.map((conversation) => (
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
            <Avatar address={conversation.conversationId} size={40} />
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 500 }}>
                Project #{conversation.project.projectId} ·{" "}
                {conversation.project.chainId}
              </div>
              <div className="mxHint">
                {conversation.role} ·{" "}
                {conversation.state === "active"
                  ? "active"
                  : conversation.state}{" "}
                · {conversation.lastPosition} events
              </div>
            </div>
            <span className="mxChip">{conversation.deliveryPurpose}</span>
          </button>
        ))
      )}
      {claimOpen ? (
        <ClaimPurchaseDialog
          onClose={() => setClaimOpen(false)}
          onClaimed={() => void reload()}
          onOpened={(conversationId) => {
            setClaimOpen(false);
            void reload().then(() => {
              setSelected(
                (current) =>
                  current ?? {
                    conversationId,
                    state: "active",
                    deliveryPurpose: "purchase_support",
                    role: "customer",
                    lastPosition: "1",
                    lastActivityAt: "",
                    project: { chainId: "", projectId: "" },
                  },
              );
            });
          }}
        />
      ) : null}
    </div>
  );
}

function PushToggle() {
  const [state, setState] = useState<PushState | "unknown">("unknown");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const timer = setTimeout(
      () => void pushState().then(setState).catch(() => setState("unavailable")),
      0,
    );
    return () => clearTimeout(timer);
  }, []);

  if (state === "unknown" || state === "unavailable") return null;
  if (state === "denied") {
    return <span className="mxHint">Notifications blocked in browser settings</span>;
  }
  return (
    <button
      className="mxBtnSecondary"
      disabled={busy}
      onClick={async () => {
        setBusy(true);
        try {
          setState(state === "on" ? await disablePush() : await enablePush());
        } finally {
          setBusy(false);
        }
      }}
    >
      {state === "on" ? "Notifications on" : "Notify me"}
    </button>
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
  onClick,
}: {
  project: DiscoveredProject;
  meta: string;
  action: string;
  onClick: () => void;
}) {
  return (
    <button
      className="mxCard mxRow"
      style={{
        padding: "0.9rem 1rem",
        cursor: "pointer",
        font: "inherit",
        textAlign: "left",
        width: "100%",
      }}
      onClick={onClick}
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
          {CHAIN_NAME[project.chainId] ?? `Chain ${project.chainId}`} · {meta}
        </div>
      </div>
      <span className="mxChip">{action}</span>
    </button>
  );
}

function Discovery({ onStart }: { onStart: () => void }) {
  const { address } = useAccount();
  const [data, setData] = useState<{
    asCustomer: CustomerProject[];
    asOwner: OwnerProject[];
  } | null>(null);

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
            <ProjectRow
              key={`c-${project.chainId}-${project.projectId}`}
              project={project}
              meta={`${project.paymentsCount} payment${project.paymentsCount === 1 ? "" : "s"}`}
              action="Open support"
              onClick={onStart}
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
              onClick={onStart}
            />
          ))}
        </section>
      ) : null}
    </div>
  );
}

function ConversationView({
  conversation,
  onBack,
}: {
  conversation: ConversationSummary;
  onBack: () => void;
}) {
  const [events, setEvents] = useState<ConversationEvent[] | null>(null);
  const [messages, setMessages] = useState<Record<string, CachedMessage>>({});
  const [decryptable, setDecryptable] = useState(false);
  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
    setDecryptable(await canDecrypt(conversation.conversationId));
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
          Project #{conversation.project.projectId} support
        </h1>
      </div>
      <section
        className="mxCard"
        style={{ padding: "1.25rem", display: "grid", gap: 8 }}
      >
        {error ? <p className="mxError">{error}</p> : null}
        {events === null ? (
          <p className="mxHint">Loading transcript…</p>
        ) : (
          <ol style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 8 }}>
            {events.map((event) => {
              if (event.envelopeClass !== "application") {
                return (
                  <li key={event.position} className="mxHint" style={{ textAlign: "center" }}>
                    Membership change · #{event.position}
                  </li>
                );
              }
              const message = messages[event.envelopeId];
              const mine = message?.mine ?? false;
              return (
                <li
                  key={event.position}
                  style={{
                    display: "flex",
                    justifyContent: mine ? "flex-end" : "flex-start",
                  }}
                >
                  <span
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
                </li>
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

function ClaimPurchaseDialog({
  onClose,
  onClaimed,
  onOpened,
}: {
  onClose: () => void;
  onClaimed: () => void;
  onOpened: (conversationId: string) => void;
}) {
  const { address, chainId } = useAccount();
  const [txHash, setTxHash] = useState("");
  const [projectRefId, setProjectRefId] = useState("");
  const [logIndex, setLogIndex] = useState("0");
  const [terminal, setTerminal] = useState(
    "0x130f5dd2bd8805443cf41755253d778a75a67f53",
  );
  const [state, setState] = useState<
    | { phase: "form" }
    | { phase: "claiming" }
    | { phase: "opening" }
    | { phase: "claimed"; capability: string; validUntil: string }
    | { phase: "error"; reason: string }
  >({ phase: "form" });

  return (
    <dialog
      open
      className="mxDialog"
      style={{ position: "fixed", inset: 0, margin: "auto", zIndex: 60 }}
    >
      <form
        style={{ padding: "1.25rem", display: "grid", gap: 12 }}
        onSubmit={async (event) => {
          event.preventDefault();
          if (!address || !chainId) return;
          setState({ phase: "claiming" });
          const response = await api("POST", "/v1/eligibility/purchase-claims", {
            projectRefId: projectRefId.trim(),
            walletRef: `eip155:${chainId}:${address.toLowerCase()}`,
            transactionHash: txHash.trim().toLowerCase(),
            payLogIndex: Number(logIndex),
            terminal: terminal.trim().toLowerCase(),
          });
          if (response.status === 201) {
            const body = (await response.json()) as {
              capability: string;
              validUntil: string;
              claimHandle: string;
            };
            // The grant is live: open the encrypted channel right away -
            // plan, build the MLS group on this device, activate.
            setState({ phase: "opening" });
            try {
              const conversationId = await startConversation(body.claimHandle);
              onClaimed();
              onOpened(conversationId);
            } catch (openError) {
              setState({
                phase: "error",
                reason:
                  openError instanceof Error
                    ? openError.message
                    : "conversation_open_failed",
              });
              onClaimed();
            }
            return;
          }
          const body = (await response
            .json()
            .catch(() => ({ reasonCode: "claim_failed" }))) as {
            reasonCode?: string;
          };
          setState({
            phase: "error",
            reason: body.reasonCode ?? "claim_failed",
          });
        }}
      >
        <h2 className="mxDisplay" style={{ margin: 0, fontSize: 18 }}>
          Claim a purchase
        </h2>
        <p className="mxHint" style={{ margin: 0 }}>
          Your payment receipt is verified against finalized chain state
          through an independent RPC quorum. Nothing is sent on-chain.
        </p>
        <div>
          <label className="mxLabel">Payment transaction hash</label>
          <input
            className="mxInput"
            required
            placeholder="0x…"
            value={txHash}
            onChange={(event) => setTxHash(event.target.value)}
          />
        </div>
        <div>
          <label className="mxLabel">Project reference ID</label>
          <input
            className="mxInput"
            required
            placeholder="From the project\u2019s messaging link"
            value={projectRefId}
            onChange={(event) => setProjectRefId(event.target.value)}
          />
        </div>
        <div className="mxRow">
          <div style={{ flex: 1 }}>
            <label className="mxLabel">Pay log index</label>
            <input
              className="mxInput"
              required
              value={logIndex}
              onChange={(event) => setLogIndex(event.target.value)}
            />
          </div>
          <div style={{ flex: 2 }}>
            <label className="mxLabel">Terminal</label>
            <input
              className="mxInput"
              required
              value={terminal}
              onChange={(event) => setTerminal(event.target.value)}
            />
          </div>
        </div>
        {state.phase === "opening" ? (
          <p className="mxHint" style={{ margin: 0 }}>
            Receipt verified. Opening your encrypted channel…
          </p>
        ) : null}
        {state.phase === "claimed" ? (
          <p style={{ color: "var(--mx-melon)", margin: 0 }}>
            Verified. Your {state.capability} grant is active until{" "}
            {new Date(state.validUntil).toLocaleTimeString()}.
          </p>
        ) : null}
        {state.phase === "error" ? (
          <p className="mxError" style={{ margin: 0 }}>
            The claim was not accepted ({state.reason}).
          </p>
        ) : null}
        <div className="mxRow" style={{ justifyContent: "flex-end" }}>
          <button type="button" className="mxBtnSecondary" onClick={onClose}>
            Close
          </button>
          <button
            type="submit"
            className="mxBtnPrimary"
            disabled={state.phase === "claiming" || state.phase === "opening"}
          >
            {state.phase === "claiming"
              ? "Verifying…"
              : state.phase === "opening"
                ? "Opening…"
                : "Verify receipt"}
          </button>
        </div>
      </form>
    </dialog>
  );
}
