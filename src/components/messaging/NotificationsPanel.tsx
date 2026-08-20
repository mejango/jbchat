"use client";

import { useCallback, useEffect, useState } from "react";
import {
  disablePush,
  enablePush,
  pushState,
  type PushState,
} from "@/lib/messaging/push";
import {
  createChannel,
  deleteChannel,
  listChannels,
  verifyEmailCode,
  type ChannelsView,
  type NotificationChannel,
} from "@/lib/messaging/notify";

// The account-scoped channels a user can wire up. Browser push is handled
// separately (it is per-device). WhatsApp is listed but its sender is not
// wired yet, so it stays "pending".
export function NotificationsButton() {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button className="mxBtnSecondary" onClick={() => setOpen(true)}>
        Notifications
      </button>
      {open ? <NotificationsPanel onClose={() => setOpen(false)} /> : null}
    </>
  );
}

function NotificationsPanel({ onClose }: { onClose: () => void }) {
  const [view, setView] = useState<ChannelsView | null>(null);

  const refresh = useCallback(async () => {
    setView(await listChannels());
  }, []);

  useEffect(() => {
    const kickoff = setTimeout(() => void refresh(), 0);
    return () => clearTimeout(kickoff);
  }, [refresh]);

  const active = (kind: string) =>
    view?.channels.find((c) => c.kind === kind && c.state === "active");
  const pending = (kind: string) =>
    view?.channels.find((c) => c.kind === kind && c.state === "pending");

  return (
    <dialog
      open
      className="mxDialog"
      style={{ position: "fixed", inset: 0, margin: "auto", zIndex: 60, maxWidth: 460 }}
    >
      <div style={{ padding: "1.25rem", display: "grid", gap: 14 }}>
        <div className="mxRow" style={{ justifyContent: "space-between" }}>
          <h2 className="mxDisplay" style={{ margin: 0, fontSize: 18 }}>
            Notifications
          </h2>
          <button className="mxBtnSecondary" onClick={onClose}>
            Close
          </button>
        </div>
        <p className="mxHint" style={{ margin: 0 }}>
          Get a heads-up when you have a new message or someone wants to reach
          you. We only send &ldquo;you have activity&rdquo; &mdash; never the
          message itself.
        </p>

        <BrowserRow />

        <EmailRow
          available={view?.providers.email ?? false}
          channel={active("email")}
          pending={pending("email")}
          onChanged={refresh}
        />

        <TelegramRow
          available={view?.providers.telegram ?? false}
          channel={active("telegram")}
          onChanged={refresh}
        />

        <WhatsAppRow channel={active("whatsapp")} onChanged={refresh} />
      </div>
    </dialog>
  );
}

function Row({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="mxCard" style={{ padding: "0.9rem 1rem", display: "grid", gap: 8 }}>
      <div style={{ fontWeight: 600 }}>{title}</div>
      {children}
    </div>
  );
}

function Connected({
  display,
  onRemove,
}: {
  display: string;
  onRemove: () => void;
}) {
  return (
    <div className="mxRow" style={{ justifyContent: "space-between" }}>
      <span className="mxHint">
        Connected · <span style={{ color: "var(--mx-melon)" }}>{display}</span>
      </span>
      <button className="mxBtnSecondary" onClick={onRemove}>
        Remove
      </button>
    </div>
  );
}

function BrowserRow() {
  const [state, setState] = useState<PushState | "unknown">("unknown");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    void pushState()
      .then(setState)
      .catch(() => setState("unavailable"));
  }, []);
  if (state === "unknown") return null;
  return (
    <Row title="Browser">
      {state === "unavailable" ? (
        <span className="mxHint">Not supported in this browser.</span>
      ) : state === "denied" ? (
        <span className="mxHint">Blocked in browser settings.</span>
      ) : (
        <div className="mxRow" style={{ justifyContent: "space-between" }}>
          <span className="mxHint">
            {state === "on" ? "On for this device." : "Push to this device."}
          </span>
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
            {state === "on" ? "Turn off" : "Turn on"}
          </button>
        </div>
      )}
    </Row>
  );
}

function EmailRow({
  available,
  channel,
  pending,
  onChanged,
}: {
  available: boolean;
  channel: NotificationChannel | undefined;
  pending: NotificationChannel | undefined;
  onChanged: () => Promise<void>;
}) {
  const [email, setEmail] = useState("");
  const [channelId, setChannelId] = useState<string | null>(pending?.channelId ?? null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (channel) {
    return (
      <Row title="Email">
        <Connected
          display={channel.display}
          onRemove={async () => {
            await deleteChannel(channel.channelId);
            await onChanged();
          }}
        />
      </Row>
    );
  }
  if (!available) {
    return (
      <Row title="Email">
        <span className="mxHint">Email delivery isn&rsquo;t configured yet.</span>
      </Row>
    );
  }
  return (
    <Row title="Email">
      {channelId === null ? (
        <div className="mxRow">
          <input
            className="mxInput"
            type="email"
            placeholder="you@example.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            style={{ flex: 1 }}
          />
          <button
            className="mxBtnPrimary"
            disabled={busy || !email}
            onClick={async () => {
              setBusy(true);
              setError(null);
              const result = await createChannel("email", email);
              setBusy(false);
              if (result.status === "code_sent") setChannelId(result.channelId);
              else setError(result.status === "error" ? result.reason : "failed");
            }}
          >
            Send code
          </button>
        </div>
      ) : (
        <div className="mxRow">
          <input
            className="mxInput"
            inputMode="numeric"
            placeholder="6-digit code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            style={{ flex: 1 }}
          />
          <button
            className="mxBtnPrimary"
            disabled={busy || code.length < 6}
            onClick={async () => {
              setBusy(true);
              setError(null);
              const ok = await verifyEmailCode(channelId, code);
              setBusy(false);
              if (ok) await onChanged();
              else setError("Wrong or expired code.");
            }}
          >
            Verify
          </button>
        </div>
      )}
      {channelId !== null ? (
        <span className="mxHint">We emailed a code to {email}.</span>
      ) : null}
      {error ? <span className="mxError">{error}</span> : null}
    </Row>
  );
}

function TelegramRow({
  available,
  channel,
  onChanged,
}: {
  available: boolean;
  channel: NotificationChannel | undefined;
  onChanged: () => Promise<void>;
}) {
  const [waiting, setWaiting] = useState(false);

  // While waiting for the /start tap (and not yet linked), poll for the
  // channel to go active. Once `channel` arrives the effect re-runs and
  // clears the interval.
  useEffect(() => {
    if (!waiting || channel) return;
    const timer = setInterval(() => void onChanged(), 3000);
    return () => clearInterval(timer);
  }, [waiting, channel, onChanged]);

  if (channel) {
    return (
      <Row title="Telegram">
        <Connected
          display={channel.display}
          onRemove={async () => {
            await deleteChannel(channel.channelId);
            await onChanged();
          }}
        />
      </Row>
    );
  }
  if (!available) {
    return (
      <Row title="Telegram">
        <span className="mxHint">Telegram delivery isn&rsquo;t configured yet.</span>
      </Row>
    );
  }
  return (
    <Row title="Telegram">
      <div className="mxRow" style={{ justifyContent: "space-between" }}>
        <span className="mxHint">
          {waiting ? "Waiting for you to tap Start in Telegram…" : "Link your Telegram."}
        </span>
        <button
          className="mxBtnPrimary"
          onClick={async () => {
            const result = await createChannel("telegram", "telegram");
            if (result.status === "deep_link") {
              window.open(result.deepLink, "_blank", "noopener");
              setWaiting(true);
            }
          }}
        >
          Connect Telegram
        </button>
      </div>
    </Row>
  );
}

function WhatsAppRow({
  channel,
  onChanged,
}: {
  channel: NotificationChannel | undefined;
  onChanged: () => Promise<void>;
}) {
  const [phone, setPhone] = useState("");
  const [saved, setSaved] = useState(false);

  if (channel) {
    return (
      <Row title="WhatsApp">
        <Connected
          display={channel.display}
          onRemove={async () => {
            await deleteChannel(channel.channelId);
            await onChanged();
          }}
        />
      </Row>
    );
  }
  return (
    <Row title="WhatsApp">
      <div className="mxRow">
        <input
          className="mxInput"
          type="tel"
          placeholder="+15551234567"
          value={phone}
          onChange={(e) => setPhone(e.target.value)}
          style={{ flex: 1 }}
        />
        <button
          className="mxBtnPrimary"
          disabled={!phone}
          onClick={async () => {
            const result = await createChannel("whatsapp", phone);
            if (result.status === "pending_provider") setSaved(true);
            await onChanged();
          }}
        >
          Add
        </button>
      </div>
      <span className="mxHint">
        {saved
          ? "Saved. WhatsApp delivery turns on once we finish provider setup."
          : "WhatsApp delivery is coming soon; add your number to be ready."}
      </span>
    </Row>
  );
}
