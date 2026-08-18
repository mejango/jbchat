"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { ThemeSelectionV1 } from "@/theme/theme";
import {
  OWNED_THEME_ATTRIBUTE_VALUE,
  materializeOwnedTheme,
  type OwnedThemeMaterialization,
} from "@/theme/ownedStylesheet";
import {
  EMBED_CAPABILITIES,
  EMBED_PROTOCOL,
  type FrameBootstrapMessage,
  type FrameToHostMessage,
  type HostToFrameMessage,
} from "./protocol";
import {
  createEstablishedHostToFrameGate,
  createHostInitializationGate,
  exactOrigin,
  postExactBridgeMessage,
  randomBase64Url,
  type EmbedHostInitializationGate,
  type EmbedInboundGate,
  type ExactOrigin,
} from "./runtime";
import styles from "./EmbedProductionFrame.module.css";

type FramePhase = "checking" | "waiting" | "ready" | "closed" | "failed" | "blocked";
type OperationalFrameType = Exclude<FrameToHostMessage["type"], "frame.ready">;
type FrameOperationDraft = {
  [Type in OperationalFrameType]: {
    type: Type;
    payload: Extract<FrameToHostMessage, { type: Type }>["payload"];
  };
}[OperationalFrameType];

interface FrameChannel {
  target: WindowProxy;
  targetOrigin: ExactOrigin;
  channelId: string;
  bootstrapNonce: string;
  parentNonce: string;
  frameNonce: string;
  nextOutboundSequence: number;
  inbound: EmbedInboundGate<HostToFrameMessage>;
}

function hasThemeOverrides(theme: ThemeSelectionV1): boolean {
  return (
    theme.colors !== undefined ||
    theme.cornerStyle !== undefined ||
    theme.density !== undefined ||
    theme.typography !== undefined
  );
}

function pinnedAllowedParentOrigin(
  allowedParentOrigins: readonly string[],
): ExactOrigin | null {
  const allowed = new Set(allowedParentOrigins);
  const ancestors = window.location.ancestorOrigins;
  const candidates: string[] = [];
  if (ancestors && ancestors.length > 0) candidates.push(ancestors[0]);
  try {
    if (document.referrer) candidates.push(new URL(document.referrer).origin);
  } catch {
    // A malformed referrer never becomes authority.
  }
  for (const candidate of candidates) {
    if (!allowed.has(candidate)) continue;
    try {
      return exactOrigin(candidate);
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Production frame document body for /embed/{tenantPublicId}. The exact
 * allowed parent origins come from server configuration; the frame pins one
 * ancestor origin, runs the bounded bootstrap/init handshake, and then
 * redeems the one-use context through the same-origin BFF. Every redemption
 * failure surfaces as the single generic context-invalid outcome.
 */
export function EmbedProductionFrame({
  allowedParentOrigins,
  stylesheetNonce,
}: {
  allowedParentOrigins: readonly string[];
  stylesheetNonce?: string;
}) {
  const initializationGateRef = useRef<EmbedHostInitializationGate | null>(null);
  const channelRef = useRef<FrameChannel | null>(null);
  const [phase, setPhase] = useState<FramePhase>("checking");
  const [phaseDetail, setPhaseDetail] = useState(
    "Verifying the embedding parent origin.",
  );
  const [customTheme, setCustomTheme] =
    useState<OwnedThemeMaterialization | null>(null);

  const applyTheme = useCallback(
    (theme: ThemeSelectionV1) => {
      if (hasThemeOverrides(theme)) {
        try {
          setCustomTheme(materializeOwnedTheme(theme, stylesheetNonce));
        } catch {
          return false;
        }
      } else {
        setCustomTheme(null);
      }
      return true;
    },
    [stylesheetNonce],
  );

  const postOperation = useCallback((draft: FrameOperationDraft) => {
    const channel = channelRef.current;
    if (!channel) return false;
    const message = {
      protocol: EMBED_PROTOCOL,
      version: 1,
      channelId: channel.channelId,
      sequence: channel.nextOutboundSequence,
      peerNonce: channel.parentNonce,
      type: draft.type,
      payload: draft.payload,
    } as FrameToHostMessage;
    channel.nextOutboundSequence += 1;
    postExactBridgeMessage(channel.target, channel.targetOrigin, message);
    return true;
  }, []);

  useEffect(() => {
    let cancelled = false;
    const commitPhase = (nextPhase: FramePhase, detail: string) => {
      queueMicrotask(() => {
        if (cancelled) return;
        setPhase(nextPhase);
        setPhaseDetail(detail);
      });
    };

    if (!window.isSecureContext) {
      commitPhase("blocked", "This frame refuses to run outside a secure context.");
      return () => {
        cancelled = true;
      };
    }
    if (window.location.search !== "" || window.location.hash !== "") {
      window.history.replaceState(null, "", window.location.pathname);
      commitPhase(
        "blocked",
        "This frame refuses URL parameters. Open a fresh embed with a new context.",
      );
      return () => {
        cancelled = true;
      };
    }
    if (window.parent === window) {
      commitPhase("blocked", "This frame must be opened by a registered host page.");
      return () => {
        cancelled = true;
      };
    }
    const parentOrigin = pinnedAllowedParentOrigin(allowedParentOrigins);
    if (!parentOrigin || parentOrigin === window.location.origin) {
      commitPhase(
        "blocked",
        "The embedding page is not a registered parent origin for this tenant.",
      );
      return () => {
        cancelled = true;
      };
    }

    const bootstrapNonce = randomBase64Url(32);
    const initializationGate = createHostInitializationGate({
      expectedParentWindow: window.parent,
      expectedParentOrigin: parentOrigin,
      expectedBootstrapNonce: bootstrapNonce,
    });
    initializationGateRef.current = initializationGate;
    commitPhase("waiting", "Waiting for the host to initialize this secure frame.");
    const initializationTimeoutId = window.setTimeout(() => {
      if (channelRef.current !== null) return;
      initializationGate.destroy();
      setPhase("failed");
      setPhaseDetail("Initialization timed out. A fresh frame and context are required.");
    }, 10_000);

    const redeemContext = async (channel: FrameChannel, contextHandle: string) => {
      let redeemed = false;
      try {
        const response = await fetch("/v1/embed/context-redemptions", {
          method: "POST",
          headers: { "content-type": "application/json" },
          cache: "no-store",
          credentials: "same-origin",
          body: JSON.stringify({
            contextHandle,
            tenantPublicId: window.location.pathname.split("/").at(-1),
            parentOrigin: channel.targetOrigin,
            frameAudience: `${window.location.origin}/embed`,
            channel: {
              protocol: EMBED_PROTOCOL,
              version: 1,
              channelId: channel.channelId,
              bootstrapNonce: channel.bootstrapNonce,
              parentNonce: channel.parentNonce,
              frameNonce: channel.frameNonce,
            },
          }),
        });
        redeemed = response.ok;
      } catch {
        redeemed = false;
      }
      if (cancelled || channelRef.current !== channel) return;
      if (redeemed) {
        postOperation({
          type: "frame.auth_required",
          payload: { reason: "wallet-auth" },
        });
        commitPhase(
          "ready",
          "The secure channel is established. Sign-in is required before any messaging.",
        );
      } else {
        postOperation({
          type: "frame.error",
          payload: { code: "context-invalid", retryable: false },
        });
        commitPhase(
          "failed",
          "This embed context is not valid. Ask the host page to open a fresh one.",
        );
      }
    };

    const receiveHostMessage = (event: MessageEvent<unknown>) => {
      const activeChannel = channelRef.current;
      if (event.source === window.parent && event.origin !== parentOrigin) {
        initializationGate.destroy();
        activeChannel?.inbound.destroy();
        channelRef.current = null;
        window.clearTimeout(initializationTimeoutId);
        setPhase("failed");
        setPhaseDetail("The parent origin changed; this frame is no longer usable.");
        return;
      }
      if (!activeChannel) {
        const result = initializationGate.accept(event);
        if (!result.accepted) {
          if (result.reason === "untrusted-peer" || result.reason === "closed") {
            return;
          }
          initializationGate.destroy();
          window.clearTimeout(initializationTimeoutId);
          setPhase("failed");
          setPhaseDetail("Initialization did not match the bounded protocol.");
          return;
        }
        try {
          window.clearTimeout(initializationTimeoutId);
          const initialization = result.message;
          const frameNonce = randomBase64Url(32);
          const channel: FrameChannel = {
            target: window.parent,
            targetOrigin: parentOrigin,
            channelId: initialization.channelId,
            bootstrapNonce,
            parentNonce: initialization.payload.parentNonce,
            frameNonce,
            nextOutboundSequence: 1,
            inbound: createEstablishedHostToFrameGate({
              expectedParentWindow: window.parent,
              expectedParentOrigin: parentOrigin,
              channelId: initialization.channelId,
              frameNonce,
              initializationRequestId: initialization.requestId,
            }),
          };
          channelRef.current = channel;
          if (!applyTheme(initialization.payload.theme)) {
            throw new Error("Theme could not be safely materialized.");
          }
          const ready: FrameToHostMessage = {
            protocol: EMBED_PROTOCOL,
            version: 1,
            channelId: channel.channelId,
            sequence: 0,
            peerNonce: channel.parentNonce,
            type: "frame.ready",
            payload: {
              frameNonce,
              acceptedVersion: 1,
              capabilities: EMBED_CAPABILITIES,
            },
          };
          postExactBridgeMessage(channel.target, channel.targetOrigin, ready);
          const layout: FrameToHostMessage = {
            protocol: EMBED_PROTOCOL,
            version: 1,
            channelId: channel.channelId,
            sequence: channel.nextOutboundSequence,
            peerNonce: channel.parentNonce,
            type: "frame.layout",
            payload: { layout: window.innerWidth < 440 ? "compact" : "regular" },
          };
          channel.nextOutboundSequence += 1;
          postExactBridgeMessage(channel.target, channel.targetOrigin, layout);
          commitPhase("waiting", "Redeeming the one-use embed context.");
          void redeemContext(channel, initialization.payload.contextHandle);
        } catch {
          channelRef.current?.inbound.destroy();
          channelRef.current = null;
          setPhase("failed");
          setPhaseDetail("The browser could not establish a fresh frame channel.");
        }
        return;
      }

      const result = activeChannel.inbound.accept(event);
      if (!result.accepted) {
        if (result.reason === "untrusted-peer" || result.reason === "closed") {
          return;
        }
        postOperation({
          type: "frame.error",
          payload: { code: "channel-invalid", retryable: false },
        });
        activeChannel.inbound.destroy();
        channelRef.current = null;
        setPhase("failed");
        setPhaseDetail("A host operation failed source, origin, or protocol checks.");
        return;
      }
      switch (result.message.type) {
        case "host.set_theme":
          if (!applyTheme(result.message.payload.theme)) {
            postOperation({
              type: "frame.error",
              payload: { code: "channel-invalid", retryable: false },
            });
            activeChannel.inbound.destroy();
            channelRef.current = null;
            setPhase("failed");
            setPhaseDetail("The custom theme could not be safely materialized.");
          }
          break;
        case "host.set_locale":
          break;
        case "host.destroy":
          postOperation({ type: "frame.closed", payload: {} });
          void fetch("/v1/embed/session", {
            method: "DELETE",
            cache: "no-store",
            credentials: "same-origin",
          }).catch(() => undefined);
          activeChannel.inbound.destroy();
          channelRef.current = null;
          setPhase("closed");
          setPhaseDetail("The host closed this one-use secure frame.");
          break;
        case "host.init":
          activeChannel.inbound.destroy();
          channelRef.current = null;
          setPhase("failed");
          setPhaseDetail("Repeated initialization was rejected.");
          break;
      }
    };

    window.addEventListener("message", receiveHostMessage);
    const bootstrap: FrameBootstrapMessage = {
      protocol: EMBED_PROTOCOL,
      version: 1,
      type: "frame.bootstrap_ready",
      bootstrapNonce,
    };
    queueMicrotask(() => {
      if (cancelled || initializationGateRef.current !== initializationGate) {
        return;
      }
      postExactBridgeMessage(window.parent, parentOrigin, bootstrap);
    });

    return () => {
      cancelled = true;
      window.clearTimeout(initializationTimeoutId);
      window.removeEventListener("message", receiveHostMessage);
      initializationGate.destroy();
      initializationGateRef.current = null;
      channelRef.current?.inbound.destroy();
      channelRef.current = null;
    };
  }, [allowedParentOrigins, applyTheme, postOperation]);

  return (
    <div
      className={styles.frameRoot}
      data-embed-custom-theme={customTheme ? OWNED_THEME_ATTRIBUTE_VALUE : undefined}
      data-embed-phase={phase}
    >
      {customTheme ? (
        <style nonce={customTheme.nonce}>{customTheme.stylesheet}</style>
      ) : null}
      <main className={styles.frameMain}>
        <h1 className={styles.frameTitle}>Juicebox secure messaging</h1>
        <p className={styles.frameDetail} data-testid="embed-frame-status">
          {phaseDetail}
        </p>
      </main>
    </div>
  );
}
