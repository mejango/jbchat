"use client";

import Link from "next/link";
import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { useAccount, useConnect, useDisconnect } from "wagmi";
import {
  clearViewAs,
  getViewAs,
  getViewAsServerSnapshot,
  identityGradient,
  setViewAs,
  subscribeViewAs,
  truncateAddress,
} from "@/lib/messaging/identity";
import {
  getSession,
  getSessionServerSnapshot,
  signOut,
  subscribeSession,
} from "@/lib/messaging/client";
import { connectWithPara, isParaAvailable } from "@/providers/MessagingProviders";

const emptySubscribe = () => () => {};

/** Hydration guard without effect-time setState. */
export function useMounted(): boolean {
  return useSyncExternalStore(
    emptySubscribe,
    () => true,
    () => false,
  );
}

export function useViewAs(): string | null {
  return useSyncExternalStore(
    subscribeViewAs,
    getViewAs,
    getViewAsServerSnapshot,
  );
}

export function useMessagingSession() {
  return useSyncExternalStore(
    subscribeSession,
    getSession,
    getSessionServerSnapshot,
  );
}

export function Avatar({ address, size }: { address: string; size: number }) {
  return (
    <span
      className="mxAvatar"
      style={{
        width: size,
        height: size,
        background: identityGradient(address),
      }}
      aria-hidden
    />
  );
}

export function WalletMenu() {
  const mounted = useMounted();
  const [menuOpen, setMenuOpen] = useState(false);
  const [sheetOpen, setSheetOpen] = useState(false);
  const { address, isConnected } = useAccount();
  const { disconnect } = useDisconnect();
  const viewAs = useViewAs();
  const session = useMessagingSession();
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!menuOpen) return;
    const onClick = (event: MouseEvent) => {
      if (!menuRef.current?.contains(event.target as Node)) setMenuOpen(false);
    };
    window.addEventListener("mousedown", onClick);
    return () => window.removeEventListener("mousedown", onClick);
  }, [menuOpen]);

  if (!mounted) {
    return <button className="mxBtnPrimary">Sign in</button>;
  }

  if (viewAs) {
    return (
      <div ref={menuRef} style={{ position: "relative" }}>
        <button
          className="mxBtnSecondary mxViewAsPill"
          onClick={() => setMenuOpen((open) => !open)}
          aria-expanded={menuOpen}
        >
          <span className="mxDot" style={{ background: "var(--mx-amber-400)" }} />
          <span>
            Viewing as
            <span style={{ display: "block", fontSize: 11, fontWeight: 400 }}>
              {truncateAddress(viewAs)}
            </span>
          </span>
        </button>
        {menuOpen ? (
          <div className="mxCard mxMenu">
            <Link className="mxMenuItem" href={`/account/${viewAs}`}>
              View account page
            </Link>
            <button
              className="mxMenuItem"
              onClick={() => {
                clearViewAs();
                setMenuOpen(false);
              }}
            >
              Exit View as
            </button>
          </div>
        ) : null}
      </div>
    );
  }

  if (!isConnected || !address) {
    return (
      <>
        <button className="mxBtnPrimary" onClick={() => setSheetOpen(true)}>
          Sign in
        </button>
        {sheetOpen ? <ConnectSheet onClose={() => setSheetOpen(false)} /> : null}
      </>
    );
  }

  return (
    <div ref={menuRef} style={{ position: "relative" }}>
      <button
        className="mxBtnSecondary"
        onClick={() => setMenuOpen((open) => !open)}
        aria-expanded={menuOpen}
      >
        <span
          className="mxDot"
          style={{
            background:
              session.status === "ready"
                ? "var(--mx-melon)"
                : "var(--mx-split)",
          }}
        />
        <span style={{ textAlign: "left", lineHeight: 1.2 }}>
          <span style={{ display: "block", fontWeight: 500 }}>
            {session.status === "ready" ? "Signed in" : "Connected"}
          </span>
          <span
            style={{
              display: "block",
              fontSize: 11,
              color: "var(--mx-smoke-600)",
            }}
          >
            {truncateAddress(address)}
          </span>
        </span>
      </button>
      {menuOpen ? (
        <div className="mxCard mxMenu">
          <Link className="mxMenuItem" href={`/account/${address}`}>
            View account
          </Link>
          <button
            className="mxMenuItem"
            onClick={async () => {
              setMenuOpen(false);
              await signOut();
              disconnect();
            }}
          >
            Sign out
          </button>
          <div
            style={{
              borderTop: "1px solid var(--mx-smoke-200)",
              margin: "0.25rem 0",
            }}
          />
          <ViewAsForm onApplied={() => setMenuOpen(false)} />
        </div>
      ) : null}
    </div>
  );
}

export function ViewAsForm({ onApplied }: { onApplied?: () => void }) {
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  return (
    <form
      style={{ padding: "0.5rem 0.75rem" }}
      onSubmit={(event) => {
        event.preventDefault();
        const trimmed = value.trim();
        if (!/^0x[0-9a-fA-F]{40}$/.test(trimmed)) {
          setError("Enter a 0x address.");
          return;
        }
        setViewAs(trimmed);
        setError(null);
        setValue("");
        onApplied?.();
      }}
    >
      <label className="mxLabel" htmlFor="view-as-input">
        View as…
      </label>
      <input
        id="view-as-input"
        className="mxInput"
        placeholder="0x address"
        value={value}
        onChange={(event) => setValue(event.target.value)}
      />
      {error ? <p className="mxError">{error}</p> : null}
      <p className="mxHint" style={{ marginTop: 4 }}>
        Read-only: public account info. Messages stay end-to-end private.
      </p>
    </form>
  );
}

function ConnectSheet({ onClose }: { onClose: () => void }) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const { connectors, connectAsync } = useConnect();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    dialogRef.current?.showModal();
  }, []);

  const offerable = connectors.filter(
    (connector, index, all) =>
      connector.id !== "para" &&
      all.findIndex((candidate) => candidate.name === connector.name) === index,
  );

  return (
    <dialog
      ref={dialogRef}
      className="mxDialog"
      onClose={onClose}
      onClick={(event) => {
        if (event.target === dialogRef.current) dialogRef.current?.close();
      }}
    >
      <div style={{ padding: "1.25rem" }}>
        <h2 className="mxDisplay" style={{ margin: 0, fontSize: 18 }}>
          Sign in
        </h2>
        <p className="mxHint" style={{ marginTop: 4 }}>
          Connect the wallet you support projects with.
        </p>
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 8,
            marginTop: 16,
          }}
        >
          {isParaAvailable() ? (
            <button
              className="mxBtnSecondary"
              disabled={busy !== null}
              onClick={async () => {
                setBusy("para");
                setError(null);
                try {
                  await connectWithPara();
                  dialogRef.current?.close();
                } catch {
                  setError("Para sign-in did not complete.");
                } finally {
                  setBusy(null);
                }
              }}
            >
              Email or social (Para)
            </button>
          ) : null}
          {offerable.map((connector) => (
            <button
              key={connector.uid}
              className="mxBtnSecondary"
              disabled={busy !== null}
              onClick={async () => {
                setBusy(connector.uid);
                setError(null);
                try {
                  await connectAsync({ connector });
                  dialogRef.current?.close();
                } catch {
                  setError("That wallet did not connect.");
                } finally {
                  setBusy(null);
                }
              }}
            >
              {connector.name}
            </button>
          ))}
        </div>
        {error ? (
          <p className="mxError" style={{ marginTop: 12 }}>
            {error}
          </p>
        ) : null}
        <div style={{ borderTop: "1px solid var(--mx-smoke-200)", marginTop: 16 }}>
          <ViewAsForm onApplied={() => dialogRef.current?.close()} />
        </div>
      </div>
    </dialog>
  );
}
