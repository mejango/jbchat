import { describe, expect, it, vi } from "vitest";
import { EMBED_PROTOCOL } from "./protocol";
import { randomBase64Url } from "./runtime";
import { createEmbedHost, type CreateEmbedHostOptions } from "./hostSdk";

const MESSAGING_ORIGIN = "https://messages.example.com";
const HOST_ORIGIN = "https://juicebox.money";

interface PostedMessage {
  readonly data: Record<string, unknown>;
  readonly targetOrigin: string;
}

function createHarness(overrides: Partial<CreateEmbedHostOptions> = {}) {
  const listeners: ((event: MessageEvent<unknown>) => void)[] = [];
  const framePosts: PostedMessage[] = [];
  const frameWindow = {
    postMessage: (data: unknown, targetOrigin: string) => {
      framePosts.push({
        data: data as Record<string, unknown>,
        targetOrigin,
      });
    },
  } as unknown as WindowProxy;
  const appended: unknown[] = [];
  const timeline: { appendedBeforeListener: boolean }[] = [];
  const iframe = {
    attributes: {} as Record<string, string>,
    src: "",
    contentWindow: frameWindow,
    removed: false,
    setAttribute(name: string, value: string) {
      this.attributes[name] = value;
    },
    remove() {
      this.removed = true;
    },
  };
  const hostWindow = {
    location: { origin: HOST_ORIGIN },
    addEventListener: (_type: string, listener: (event: MessageEvent<unknown>) => void) => {
      timeline.push({ appendedBeforeListener: appended.length > 0 });
      listeners.push(listener);
    },
    removeEventListener: (_type: string, listener: (event: MessageEvent<unknown>) => void) => {
      const index = listeners.indexOf(listener);
      if (index >= 0) listeners.splice(index, 1);
    },
    setTimeout: (callback: () => void, delay: number) =>
      setTimeout(callback, delay) as unknown as number,
    clearTimeout: (id: number) => clearTimeout(id),
    document: {
      createElement: () => iframe,
    },
  } as unknown as Window;
  const container = {
    appendChild: (node: unknown) => {
      appended.push(node);
      return node;
    },
  } as unknown as Element;
  const events = {
    onReady: vi.fn(),
    onLayout: vi.fn(),
    onAuthRequired: vi.fn(),
    onClosed: vi.fn(),
    onError: vi.fn(),
  };
  const contextHandle = randomBase64Url(32);
  const host = createEmbedHost({
    messagingOrigin: MESSAGING_ORIGIN,
    tenantPublicId: "juicebox",
    contextHandle,
    container,
    hostWindow,
    events,
    ...overrides,
  });
  const deliver = (event: {
    source?: unknown;
    origin?: string;
    data: unknown;
  }) => {
    for (const listener of [...listeners]) {
      listener({
        source: event.source ?? frameWindow,
        origin: event.origin ?? MESSAGING_ORIGIN,
        data: event.data,
        ports: [],
      } as unknown as MessageEvent<unknown>);
    }
  };
  return {
    host,
    events,
    contextHandle,
    frameWindow,
    framePosts,
    iframe,
    appended,
    timeline,
    listeners,
    deliver,
  };
}

function bootstrapReady(bootstrapNonce: string) {
  return {
    protocol: EMBED_PROTOCOL,
    version: 1,
    type: "frame.bootstrap_ready",
    bootstrapNonce,
  };
}

function establish(harness: ReturnType<typeof createHarness>) {
  const bootstrapNonce = randomBase64Url(32);
  harness.deliver({ data: bootstrapReady(bootstrapNonce) });
  const init = harness.framePosts.at(-1)!;
  const payload = init.data.payload as Record<string, string>;
  const frameNonce = randomBase64Url(32);
  harness.deliver({
    data: {
      protocol: EMBED_PROTOCOL,
      version: 1,
      channelId: init.data.channelId,
      sequence: 0,
      peerNonce: payload.parentNonce,
      type: "frame.ready",
      payload: {
        frameNonce,
        acceptedVersion: 1,
        capabilities: [
          "opaque-context-v1",
          "semantic-theme-v1",
          "coarse-unread-v1",
          "fixed-top-level-v1",
        ],
      },
    },
  });
  return { init, frameNonce, parentNonce: payload.parentNonce };
}

describe("embed host SDK", () => {
  it("constructs the fixed sandboxed iframe with the listener installed first", () => {
    const harness = createHarness();
    expect(harness.timeline[0]).toEqual({ appendedBeforeListener: false });
    expect(harness.appended).toHaveLength(1);
    expect(harness.iframe.src).toBe(`${MESSAGING_ORIGIN}/embed/juicebox`);
    expect(harness.iframe.attributes.sandbox).toBe("allow-scripts allow-same-origin");
    expect(harness.iframe.attributes.allow).toBe("");
    expect(harness.iframe.attributes.referrerpolicy).toBe("no-referrer");
    expect(harness.host.state()).toBe("connecting");
    harness.host.destroy();
  });

  it("initializes exactly once with the exact target origin and drops the handle", () => {
    const harness = createHarness();
    const bootstrapNonce = randomBase64Url(32);
    harness.deliver({ data: bootstrapReady(bootstrapNonce) });
    expect(harness.framePosts).toHaveLength(1);
    const init = harness.framePosts[0];
    expect(init.targetOrigin).toBe(MESSAGING_ORIGIN);
    expect(init.data.type).toBe("host.init");
    const payload = init.data.payload as Record<string, string>;
    expect(payload.bootstrapNonce).toBe(bootstrapNonce);
    expect(payload.contextHandle).toBe(harness.contextHandle);
    harness.deliver({ data: bootstrapReady(randomBase64Url(32)) });
    expect(harness.host.state()).toBe("failed");
    expect(harness.iframe.removed).toBe(true);
    expect(harness.events.onError).toHaveBeenCalledWith("channel-invalid", false);
  });

  it("reaches ready, forwards operations, and posts themed updates with the frame nonce", () => {
    const harness = createHarness();
    const { init, frameNonce } = establish(harness);
    expect(harness.host.state()).toBe("ready");
    expect(harness.events.onReady).toHaveBeenCalledTimes(1);

    harness.deliver({
      data: {
        protocol: EMBED_PROTOCOL,
        version: 1,
        channelId: init.data.channelId,
        sequence: 1,
        peerNonce: init.data.payload
          ? (init.data.payload as Record<string, string>).parentNonce
          : "",
        type: "frame.layout",
        payload: { layout: "compact" },
      },
    });
    expect(harness.events.onLayout).toHaveBeenCalledWith("compact");

    expect(harness.host.setTheme({ version: 1, preset: "juicebox" })).toBe(true);
    const themed = harness.framePosts.at(-1)!;
    expect(themed.data.type).toBe("host.set_theme");
    expect(themed.data.peerNonce).toBe(frameNonce);
    expect(themed.targetOrigin).toBe(MESSAGING_ORIGIN);
    harness.host.destroy();
    expect(harness.framePosts.at(-1)!.data.type).toBe("host.destroy");
    expect(harness.iframe.removed).toBe(true);
    expect(harness.listeners).toHaveLength(0);
  });

  it("ignores unrelated windows and fails closed on origin drift", () => {
    const harness = createHarness();
    harness.deliver({
      source: { other: true },
      data: bootstrapReady(randomBase64Url(32)),
    });
    expect(harness.framePosts).toHaveLength(0);
    expect(harness.host.state()).toBe("connecting");
    harness.deliver({
      origin: "https://attacker.example",
      data: bootstrapReady(randomBase64Url(32)),
    });
    expect(harness.host.state()).toBe("failed");
    expect(harness.events.onError).toHaveBeenCalledWith("channel-invalid", false);
  });

  it("refuses same-origin messaging, malformed tenants, and malformed handles", () => {
    expect(() =>
      createHarness({ messagingOrigin: HOST_ORIGIN }),
    ).toThrow(/cross-origin/);
    expect(() => createHarness({ tenantPublicId: "Bad_Tenant" })).toThrow(
      /tenant/,
    );
    expect(() => createHarness({ contextHandle: "short" })).toThrow(/handle/);
  });

  it("surfaces the generic context-invalid outcome from the frame", () => {
    const harness = createHarness();
    const { init } = establish(harness);
    harness.deliver({
      data: {
        protocol: EMBED_PROTOCOL,
        version: 1,
        channelId: init.data.channelId,
        sequence: 1,
        peerNonce: (init.data.payload as Record<string, string>).parentNonce,
        type: "frame.error",
        payload: { code: "context-invalid", retryable: false },
      },
    });
    expect(harness.events.onError).toHaveBeenCalledWith("context-invalid", false);
    harness.host.destroy();
  });
});
