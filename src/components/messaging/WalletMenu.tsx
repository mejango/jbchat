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
import {
  BrandMark,
  OAUTH_METHODS,
  WalletFallbackMark,
  offerableWallets,
} from "./brandMarks";

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
  const [entry, setEntry] = useState("");
  const [viewAsOpen, setViewAsOpen] = useState(false);
  const para = isParaAvailable();

  useEffect(() => {
    dialogRef.current?.showModal();
  }, []);

  const startPara = async () => {
    setBusy("para");
    setError(null);
    try {
      await connectWithPara();
      dialogRef.current?.close();
    } catch {
      setError("Sign-in did not complete.");
    } finally {
      setBusy(null);
    }
  };

  const squareButton = {
    width: 40,
    height: 40,
    padding: 0,
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
  } as const;

  return (
    <dialog
      ref={dialogRef}
      className="mxDialog"
      onClose={onClose}
      onClick={(event) => {
        if (event.target === dialogRef.current) dialogRef.current?.close();
      }}
    >
      <div style={{ padding: "1.25rem", minWidth: 340 }}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-start",
          }}
        >
          <div>
            <h2 className="mxDisplay" style={{ margin: 0, fontSize: 20 }}>
              Sign in
            </h2>
            <p className="mxHint" style={{ margin: "4px 0 0" }}>
              {para
                ? "You will receive a code."
                : "Connect the wallet you support projects with."}
            </p>
          </div>
          <button
            type="button"
            aria-label="Close"
            onClick={() => dialogRef.current?.close()}
            style={{
              border: "none",
              background: "none",
              cursor: "pointer",
              fontSize: 18,
              lineHeight: 1,
              padding: 4,
            }}
          >
            ✕
          </button>
        </div>

        {para ? (
          <>
            <form
              style={{ marginTop: 16 }}
              onSubmit={(event) => {
                event.preventDefault();
                void startPara();
              }}
            >
              <input
                className="mxInput"
                type="text"
                value={entry}
                onChange={(event) => setEntry(event.target.value)}
                placeholder="you@email.com | +1 222 333 4444"
                aria-label="Email address or phone number"
                autoComplete="email"
              />
              <div
                style={{
                  display: "flex",
                  justifyContent: "flex-end",
                  marginTop: 10,
                }}
              >
                <button
                  className="mxBtnPrimary"
                  type="submit"
                  disabled={busy !== null}
                >
                  Continue
                </button>
              </div>
            </form>
            <p className="mxHint" style={{ margin: "14px 0 6px", fontSize: 12 }}>
              Or, use socials
            </p>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {OAUTH_METHODS.map(({ method, label }) => (
                <button
                  key={method}
                  type="button"
                  className="mxBtnSecondary"
                  style={squareButton}
                  title={label}
                  aria-label={label}
                  disabled={busy !== null}
                  onClick={() => void startPara()}
                >
                  <BrandMark method={method} />
                </button>
              ))}
            </div>
            <p className="mxHint" style={{ margin: "14px 0 6px", fontSize: 12 }}>
              … or, a wallet.
            </p>
          </>
        ) : (
          <div style={{ marginTop: 16 }} />
        )}

        <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
          {offerableWallets(connectors).map((connector) => (
            <button
              key={connector.uid}
              type="button"
              className="mxBtnSecondary"
              style={squareButton}
              title={connector.name}
              aria-label={connector.name}
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
              {connector.icon ? (
                // eslint-disable-next-line @next/next/no-img-element
                <img
                  src={connector.icon}
                  alt=""
                  style={{ width: 20, height: 20 }}
                />
              ) : (
                <WalletFallbackMark id={connector.id} />
              )}
            </button>
          ))}
        </div>

        {error ? (
          <p className="mxError" style={{ marginTop: 12 }}>
            {error}
          </p>
        ) : null}

        <div
          style={{ borderTop: "1px solid var(--mx-smoke-200)", marginTop: 16 }}
        >
          {viewAsOpen ? (
            <ViewAsForm onApplied={() => dialogRef.current?.close()} />
          ) : (
            <button
              type="button"
              className="mxHint"
              style={{
                border: "none",
                background: "none",
                cursor: "pointer",
                padding: "0.75rem 0 0",
                textDecoration: "underline",
                font: "inherit",
                fontSize: 13,
              }}
              onClick={() => setViewAsOpen(true)}
            >
              View as…
            </button>
          )}
        </div>
      </div>
    </dialog>
  );
}
