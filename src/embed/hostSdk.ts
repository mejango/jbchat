import type { ThemeSelectionV1 } from "@/theme/theme";
import {
  EMBED_PROTOCOL,
  type EmbedLayout,
  type EmbedLocale,
  type EmbedTopLevelReason,
  type FrameToHostMessage,
  type HostToFrameMessage,
} from "./protocol";
import {
  createFrameBootstrapGate,
  createFrameToHostGate,
  exactOrigin,
  postExactBridgeMessage,
  randomBase64Url,
  type EmbedFrameBootstrapGate,
  type EmbedInboundGate,
  type ExactOrigin,
} from "./runtime";

const TENANT_PUBLIC_ID = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const CONTEXT_HANDLE = /^[A-Za-z0-9_-]{43,1024}$/;
const DEFAULT_INITIALIZATION_TIMEOUT_MILLISECONDS = 10_000;

export type EmbedHostState = "connecting" | "ready" | "closed" | "failed";

export interface EmbedHostEvents {
  readonly onReady?: () => void;
  readonly onLayout?: (layout: EmbedLayout) => void;
  readonly onUnread?: (hasUnread: boolean) => void;
  readonly onAuthRequired?: (
    reason: "wallet-auth" | "device-enrollment" | "storage-recovery",
  ) => void;
  readonly onOpenTopLevel?: (reason: EmbedTopLevelReason) => void;
  readonly onClosed?: () => void;
  readonly onError?: (
    code: "context-invalid" | "channel-invalid" | "temporarily-unavailable",
    retryable: boolean,
  ) => void;
}

export interface CreateEmbedHostOptions {
  /** Compiled messaging origin constant; never derived from page data. */
  readonly messagingOrigin: string;
  readonly tenantPublicId: string;
  /** One-use opaque capability. The SDK sends it once and drops it. */
  readonly contextHandle: string;
  readonly container: Pick<Element, "appendChild">;
  readonly theme?: ThemeSelectionV1;
  readonly locale?: EmbedLocale;
  readonly title?: string;
  readonly initializationTimeoutMilliseconds?: number;
  /** Local protocol lab only; production integrations must never set this. */
  readonly allowLoopbackHttp?: boolean;
  readonly events?: EmbedHostEvents;
  readonly hostWindow?: Window;
  readonly hostDocument?: Document;
}

export interface EmbedHost {
  readonly iframe: HTMLIFrameElement;
  readonly state: () => EmbedHostState;
  readonly setTheme: (theme: ThemeSelectionV1) => boolean;
  readonly setLocale: (locale: EmbedLocale) => boolean;
  readonly destroy: () => void;
}

interface HostChannel {
  target: WindowProxy;
  targetOrigin: ExactOrigin;
  channelId: string;
  parentNonce: string;
  frameNonce: string | null;
  nextOutboundSequence: number;
  inbound: EmbedInboundGate<FrameToHostMessage>;
}

/**
 * The supported host integration entry point from embed-contract.md: the SDK
 * owns iframe construction with the fixed sandbox, installs its message
 * listener before the frame loads, names the exact compiled messaging origin
 * on every postMessage, sends the one-use context handle only inside
 * host.init, and fails closed on any source, origin, channel, sequence, or
 * nonce violation.
 */
export function createEmbedHost(options: CreateEmbedHostOptions): EmbedHost {
  const hostWindow = options.hostWindow ?? window;
  const hostDocument = options.hostDocument ?? hostWindow.document;
  const events = options.events ?? {};
  const messagingOrigin = exactOrigin(options.messagingOrigin, {
    allowLoopbackHttp: options.allowLoopbackHttp === true,
  });
  if (messagingOrigin === hostWindow.location.origin) {
    throw new Error("The messaging origin must be cross-origin from the host page.");
  }
  if (!TENANT_PUBLIC_ID.test(options.tenantPublicId)) {
    throw new Error("The tenant public ID is not registered routing data.");
  }
  if (!CONTEXT_HANDLE.test(options.contextHandle)) {
    throw new Error("The context handle is not a bounded opaque capability.");
  }

  let state: EmbedHostState = "connecting";
  let contextHandle: string | null = options.contextHandle;
  let bootstrapGate: EmbedFrameBootstrapGate | null = null;
  let channel: HostChannel | null = null;
  let destroyed = false;

  const iframe = hostDocument.createElement("iframe");
  iframe.setAttribute("title", options.title ?? "Juicebox secure messaging");
  iframe.setAttribute("sandbox", "allow-scripts allow-same-origin");
  iframe.setAttribute("allow", "");
  iframe.setAttribute("referrerpolicy", "no-referrer");

  const teardownChannel = () => {
    bootstrapGate?.destroy();
    bootstrapGate = null;
    channel?.inbound.destroy();
    channel = null;
    contextHandle = null;
  };

  const failClosed = (
    code: "context-invalid" | "channel-invalid" | "temporarily-unavailable",
  ) => {
    if (destroyed) return;
    destroyed = true;
    state = "failed";
    hostWindow.clearTimeout(initializationTimeoutId);
    hostWindow.removeEventListener("message", receiveFrameMessage);
    teardownChannel();
    iframe.remove();
    events.onError?.(code, false);
  };

  const postEstablished = (
    draft:
      | { type: "host.set_theme"; payload: { theme: ThemeSelectionV1 } }
      | { type: "host.set_locale"; payload: { locale: EmbedLocale } }
      | { type: "host.destroy"; payload: Record<string, never> },
  ): boolean => {
    if (!channel || channel.frameNonce === null) return false;
    const message = {
      protocol: EMBED_PROTOCOL,
      version: 1,
      channelId: channel.channelId,
      sequence: channel.nextOutboundSequence,
      peerNonce: channel.frameNonce,
      type: draft.type,
      payload: draft.payload,
    } as HostToFrameMessage;
    channel.nextOutboundSequence += 1;
    postExactBridgeMessage(channel.target, channel.targetOrigin, message);
    return true;
  };

  const receiveFrameMessage = (event: MessageEvent<unknown>) => {
    if (destroyed) return;
    const frameWindow = iframe.contentWindow;
    if (!frameWindow || event.source !== frameWindow) return;
    if (event.origin !== messagingOrigin) {
      failClosed("channel-invalid");
      return;
    }
    if (!channel) {
      if (!bootstrapGate) {
        failClosed("channel-invalid");
        return;
      }
      const bootstrapResult = bootstrapGate.accept(event);
      if (!bootstrapResult.accepted) {
        failClosed("channel-invalid");
        return;
      }
      const handle = contextHandle;
      if (handle === null) {
        failClosed("context-invalid");
        return;
      }
      const channelId = randomBase64Url(24);
      const parentNonce = randomBase64Url(32);
      const initializationRequestId = randomBase64Url(18);
      channel = {
        target: frameWindow,
        targetOrigin: messagingOrigin,
        channelId,
        parentNonce,
        frameNonce: null,
        nextOutboundSequence: 1,
        inbound: createFrameToHostGate({
          expectedFrameWindow: frameWindow,
          expectedFrameOrigin: messagingOrigin,
          channelId,
          parentNonce,
        }),
      };
      bootstrapGate.destroy();
      bootstrapGate = null;
      contextHandle = null;
      const initialization: HostToFrameMessage = {
        protocol: EMBED_PROTOCOL,
        version: 1,
        channelId,
        sequence: 0,
        requestId: initializationRequestId,
        type: "host.init",
        payload: {
          bootstrapNonce: bootstrapResult.message.bootstrapNonce,
          parentNonce,
          contextHandle: handle,
          locale: options.locale ?? "en",
          theme: options.theme ?? { version: 1, preset: "neutral" },
        },
      };
      postExactBridgeMessage(frameWindow, messagingOrigin, initialization);
      return;
    }

    const result = channel.inbound.accept(event);
    if (!result.accepted) {
      if (result.reason === "untrusted-peer" || result.reason === "closed") {
        return;
      }
      failClosed("channel-invalid");
      return;
    }
    const message = result.message;
    switch (message.type) {
      case "frame.ready":
        if (channel.frameNonce !== null) return;
        channel.frameNonce = message.payload.frameNonce;
        hostWindow.clearTimeout(initializationTimeoutId);
        state = "ready";
        events.onReady?.();
        break;
      case "frame.layout":
        events.onLayout?.(message.payload.layout);
        break;
      case "frame.unread":
        events.onUnread?.(message.payload.hasUnread);
        break;
      case "frame.auth_required":
        events.onAuthRequired?.(message.payload.reason);
        break;
      case "frame.open_top_level":
        events.onOpenTopLevel?.(message.payload.reason);
        break;
      case "frame.closed":
        state = "closed";
        events.onClosed?.();
        break;
      case "frame.error":
        events.onError?.(message.payload.code, message.payload.retryable);
        break;
    }
  };

  // The listener is installed before the frame can load or speak.
  hostWindow.addEventListener("message", receiveFrameMessage);
  const initializationTimeoutId = hostWindow.setTimeout(() => {
    if (state === "connecting") failClosed("temporarily-unavailable");
  }, options.initializationTimeoutMilliseconds ??
    DEFAULT_INITIALIZATION_TIMEOUT_MILLISECONDS);
  iframe.src = `${messagingOrigin}/embed/${options.tenantPublicId}`;
  options.container.appendChild(iframe);
  bootstrapGate = createFrameBootstrapGate({
    expectedFrameWindow: iframe.contentWindow as WindowProxy,
    expectedFrameOrigin: messagingOrigin,
  });

  return Object.freeze({
    iframe,
    state: () => state,
    setTheme: (theme: ThemeSelectionV1) =>
      postEstablished({ type: "host.set_theme", payload: { theme } }),
    setLocale: (locale: EmbedLocale) =>
      postEstablished({ type: "host.set_locale", payload: { locale } }),
    destroy: () => {
      if (destroyed) return;
      postEstablished({ type: "host.destroy", payload: {} });
      destroyed = true;
      state = "closed";
      hostWindow.clearTimeout(initializationTimeoutId);
      hostWindow.removeEventListener("message", receiveFrameMessage);
      teardownChannel();
      iframe.remove();
    },
  });
}
