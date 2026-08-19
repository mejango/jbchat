"use client";

import Link from "next/link";

import { MessagingProviders } from "@/providers/MessagingProviders";
import { truncateAddress } from "@/lib/messaging/identity";
import {
  Avatar,
  WalletMenu,
  useMessagingSession,
  useMounted,
  useViewAs,
} from "./WalletMenu";
import { clearViewAs, setViewAs } from "@/lib/messaging/identity";

export function AccountView({ address }: { address: string }) {
  const normalized = /^0x[0-9a-fA-F]{40}$/.test(address)
    ? address.toLowerCase()
    : null;
  return (
    <MessagingProviders>
      <div className="mxApp">
        <header className="mxHeader">
          <Link
            href="/"
            className="mxDisplay"
            style={{ color: "inherit", textDecoration: "none", fontSize: 16 }}
          >
            Fruitful
          </Link>
          <WalletMenu />
        </header>
        <main className="mxShell">
          {normalized ? (
            <AccountBody address={normalized} />
          ) : (
            <p className="mxError">That is not a valid 0x address.</p>
          )}
        </main>
      </div>
    </MessagingProviders>
  );
}

function AccountBody({ address }: { address: string }) {
  const mounted = useMounted();
  const session = useMessagingSession();
  const viewAs = useViewAs();
  const isYou =
    mounted &&
    session.status === "ready" &&
    session.walletAddress === address;
  const isViewingThis = mounted && viewAs === address;

  return (
    <div style={{ display: "grid", gap: 16 }}>
      <section className="mxCard mxRow" style={{ padding: "1.5rem" }}>
        <Avatar address={address} size={64} />
        <div style={{ flex: 1 }}>
          <h1 className="mxDisplay" style={{ margin: 0, fontSize: 22 }}>
            {truncateAddress(address)}
          </h1>
          <p className="mxHint" style={{ margin: 0 }}>
            {isYou ? "Your account" : "Public account view"}
          </p>
        </div>
        {mounted ? (
          <button
            className="mxBtnSecondary"
            onClick={() =>
              isViewingThis ? clearViewAs() : setViewAs(address)
            }
          >
            {isViewingThis ? "Exit View as" : "View site as this account"}
          </button>
        ) : null}
      </section>
      <section className="mxCard" style={{ padding: "1.5rem" }}>
        <h2 className="mxDisplay" style={{ marginTop: 0, fontSize: 16 }}>
          What is public here
        </h2>
        <p style={{ color: "var(--mx-smoke-700)" }}>
          Only what the chain already reveals: this address and its on-chain
          payments to Juicebox projects. Enrollment status, devices,
          conversations, and every message are end-to-end private by design
          - not even the messaging service can read them, so neither can a
          viewer.
        </p>
        {isYou ? (
          <p className="mxHint">
            You are signed in on this device (installation{" "}
            {session.installationId?.slice(0, 8)}…). Manage your inbox from
            the <Link href="/">home page</Link>.
          </p>
        ) : null}
      </section>
    </div>
  );
}
