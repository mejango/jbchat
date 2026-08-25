"use client";

import { useCallback, useEffect, useState } from "react";
import {
  conversationDetail,
  disableRelay,
  enableRelay,
  type RelayStatus,
} from "@/lib/messaging/conversation";
import { listChannels } from "@/lib/messaging/notify";

// ADR 0006 §2/§3: the relay is an explicit, per-conversation seat the
// member enables; the copy states exactly what it costs. Nothing here is
// on by default.
export function RelayButton({ conversationId }: { conversationId: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button className="mxBtnSecondary" onClick={() => setOpen(true)}>
        Relay
      </button>
      {open ? (
        <RelayPanel conversationId={conversationId} onClose={() => setOpen(false)} />
      ) : null}
    </>
  );
}

function RelayPanel({
  conversationId,
  onClose,
}: {
  conversationId: string;
  onClose: () => void;
}) {
  const [status, setStatus] = useState<RelayStatus | null>(null);
  const [telegramLinked, setTelegramLinked] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const detail = await conversationDetail(conversationId);
    setStatus(detail.relay ?? null);
    const channels = await listChannels();
    setTelegramLinked(
      channels.channels.some(
        (channel) => channel.kind === "telegram" && channel.state === "active",
      ),
    );
  }, [conversationId]);

  useEffect(() => {
    const kickoff = setTimeout(() => void refresh(), 0);
    return () => clearTimeout(kickoff);
  }, [refresh]);

  const run = async (action: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await action();
      await refresh();
    } catch (failure) {
      const code = failure instanceof Error ? failure.message : "relay_refused";
      setError(
        code === "channel_not_verified"
          ? "Link Telegram under Notifications first."
          : code === "device_cannot_commit"
            ? "This device does not hold the conversation keys. Open it on the device that joined."
            : code === "bridge_unavailable"
              ? "The relay service is not available right now."
              : "The relay could not be changed. Try again.",
      );
    } finally {
      setBusy(false);
    }
  };

  const mine = status?.mine.telegram ?? "none";
  return (
    <dialog
      open
      className="mxDialog"
      style={{ position: "fixed", inset: 0, margin: "auto", zIndex: 60, maxWidth: 460 }}
    >
      <div style={{ padding: "1.25rem", display: "grid", gap: 14 }}>
        <div className="mxRow" style={{ justifyContent: "space-between" }}>
          <h2 className="mxDisplay" style={{ margin: 0, fontSize: 18 }}>
            Telegram relay
          </h2>
          <button className="mxBtnSecondary" onClick={onClose}>
            Close
          </button>
        </div>
        <p className="mxHint" style={{ margin: 0 }}>
          Read and answer this conversation from Telegram. A relay is a
          member of the conversation that everyone can see in the roster.
        </p>
        {status ? (
          <p style={{ margin: 0 }}>{status.statement}</p>
        ) : (
          <p className="mxHint">Loading…</p>
        )}
        {status?.seats.filter((seat) => !seat.mine).map((seat) => (
          <p key={seat.installationId} className="mxHint" style={{ margin: 0 }}>
            {seat.role === "customer" ? "The customer’s" : "The project’s"}{" "}
            Telegram relay can read this conversation.
          </p>
        ))}
        {error ? <p className="mxError">{error}</p> : null}
        <div className="mxRow">
          {mine === "active" ? (
            <button
              className="mxBtnSecondary"
              disabled={busy}
              onClick={() => void run(() => disableRelay(conversationId))}
            >
              {busy ? "Working…" : "Disable relay"}
            </button>
          ) : mine === "pending" ? (
            <p className="mxHint" style={{ margin: 0 }}>
              The relay is joining. Messages resume once the transparency
              witness co-signs.
            </p>
          ) : (
            <button
              className="mxBtn"
              disabled={busy || telegramLinked === false}
              onClick={() => void run(() => enableRelay(conversationId, "telegram"))}
            >
              {busy ? "Working…" : "Relay to Telegram"}
            </button>
          )}
        </div>
        {telegramLinked === false ? (
          <p className="mxHint" style={{ margin: 0 }}>
            Link Telegram under Notifications to enable the relay.
          </p>
        ) : null}
        {mine === "active" ? (
          <p className="mxHint" style={{ margin: 0 }}>
            Disabling removes the relay from the conversation; messages sent
            afterwards are sealed to your devices only.
          </p>
        ) : null}
      </div>
    </dialog>
  );
}
