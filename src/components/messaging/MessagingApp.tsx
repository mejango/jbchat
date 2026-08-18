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
            <span
              className="mxAvatar"
              style={{
                width: 36,
                height: 36,
                background: "var(--mx-bluebs)",
                display: "inline-flex",
                alignItems: "center",
                justifyContent: "center",
                color: "white",
                fontWeight: 600,
              }}
            >
              ✉
            </span>
            <div>
              <div className="mxDisplay" style={{ fontSize: 16 }}>
                Juicebox Messaging
              </div>
              <div className="mxHint">Private project support</div>
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
            ? "Chain verification is unavailable for this wallet\u2019s network right now. Contract wallets are not yet supported - use an EOA."
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
        <button className="mxBtnSecondary" onClick={() => setClaimOpen(true)}>
          Claim a purchase
        </button>
      </div>
      {error ? <p className="mxError">{error}</p> : null}
      {conversations === null ? (
        <p className="mxHint">Loading your inbox…</p>
      ) : conversations.length === 0 ? (
        <section className="mxCard" style={{ padding: "2rem" }}>
          <h2 className="mxDisplay" style={{ marginTop: 0, fontSize: 17 }}>
            No conversations yet
          </h2>
          <p style={{ color: "var(--mx-smoke-700)" }}>
            Claim a purchase receipt to unlock a private support channel with
            that project&apos;s team. Opening the encrypted channel itself ships
            with the device messaging core, which is rolling out - your
            grant will be waiting.
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
        />
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
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      const response = await api(
        "GET",
        `/v1/conversations/${conversation.conversationId}/events`,
      );
      if (!response.ok) {
        setError("This conversation\u2019s transcript could not be loaded.");
        return;
      }
      const body = (await response.json()) as { events: ConversationEvent[] };
      setEvents(body.events);
    })();
  }, [conversation.conversationId]);

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
      <section className="mxCard" style={{ padding: "1.25rem" }}>
        {error ? <p className="mxError">{error}</p> : null}
        {events === null ? (
          <p className="mxHint">Loading transcript…</p>
        ) : (
          <ol style={{ listStyle: "none", margin: 0, padding: 0 }}>
            {events.map((event) => (
              <li
                key={event.position}
                className="mxRow"
                style={{ padding: "0.5rem 0" }}
              >
                <span className="mxChip">#{event.position}</span>
                <span style={{ color: "var(--mx-smoke-700)" }}>
                  {event.envelopeClass === "mls_commit"
                    ? "Membership change (encrypted commit)"
                    : event.envelopeClass === "external_proposal"
                      ? "Roster proposal"
                      : "Encrypted message"}{" "}
                  · {event.envelopeBytes} bytes
                </span>
              </li>
            ))}
          </ol>
        )}
        <p className="mxHint" style={{ marginTop: 12 }}>
          Message contents decrypt only on enrolled devices running the
          messaging core. This device can verify the transcript&apos;s order and
          integrity, which is what you see above.
        </p>
      </section>
    </div>
  );
}

function ClaimPurchaseDialog({
  onClose,
  onClaimed,
}: {
  onClose: () => void;
  onClaimed: () => void;
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
            };
            setState({
              phase: "claimed",
              capability: body.capability,
              validUntil: body.validUntil,
            });
            onClaimed();
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
            disabled={state.phase === "claiming"}
          >
            {state.phase === "claiming" ? "Verifying…" : "Verify receipt"}
          </button>
        </div>
      </form>
    </dialog>
  );
}
