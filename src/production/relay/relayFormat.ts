/**
 * Channel-facing message rendering for the ADR 0006 relay. Pure functions:
 * no I/O, no secrets. The relay forwards the SAME plaintext the member
 * would read in the app, prefixed with enough context to tell
 * conversations apart in a flat channel like a Telegram DM.
 */

export interface RelayEnvelopeContext {
  readonly projectName: string | null;
  readonly projectId: string;
  readonly senderRole: string;
  /** Short conversation tag the member can use to address replies. */
  readonly tag: string;
}

/** Outbound: one forwarded message. */
export function renderOutbound(
  context: RelayEnvelopeContext,
  text: string,
): string {
  const project = context.projectName ?? `Project #${context.projectId}`;
  const who = context.senderRole === "customer" ? "Customer" : "Team";
  return `[${context.tag}] ${project} — ${who}:\n${text}`;
}

/**
 * A stable, human-typeable conversation tag: the first 4 hex chars of the
 * conversation id. Collisions inside ONE member's relayed set are resolved
 * by the disambiguation prompt, never guessed.
 */
export function conversationTag(conversationId: string): string {
  return conversationId.replace(/-/g, "").slice(0, 4);
}

export type InboundRoute =
  | { readonly kind: "send"; readonly conversationId: string; readonly text: string }
  | { readonly kind: "prompt"; readonly options: readonly RelayEnvelopeContext[] }
  | { readonly kind: "ignore" };

/**
 * Route an inbound channel message to a conversation. A leading [tag]
 * addresses a specific conversation; without one, a single active relayed
 * conversation receives the message, and several force a prompt.
 */
export function routeInbound(
  text: string,
  conversations: readonly { readonly conversationId: string; readonly context: RelayEnvelopeContext }[],
): InboundRoute {
  const trimmed = text.trim();
  if (trimmed.length === 0 || trimmed.startsWith("/")) {
    return { kind: "ignore" };
  }
  const tagged = trimmed.match(/^\[([0-9a-f]{4})\]\s*([\s\S]+)$/i);
  if (tagged) {
    const match = conversations.find(
      (candidate) =>
        conversationTag(candidate.conversationId) === tagged[1].toLowerCase(),
    );
    if (match) {
      return {
        kind: "send",
        conversationId: match.conversationId,
        text: tagged[2].trim(),
      };
    }
  }
  if (conversations.length === 1) {
    return {
      kind: "send",
      conversationId: conversations[0].conversationId,
      text: trimmed,
    };
  }
  if (conversations.length === 0) return { kind: "ignore" };
  return {
    kind: "prompt",
    options: conversations.map((candidate) => candidate.context),
  };
}

/** The prompt asking the member to address their reply. */
export function renderPrompt(
  options: readonly RelayEnvelopeContext[],
): string {
  const lines = options.map(
    (option) =>
      `[${option.tag}] ${option.projectName ?? `Project #${option.projectId}`}`,
  );
  return [
    "You have several relayed chats. Start your reply with the tag:",
    ...lines,
    'e.g. "[' + options[0].tag + '] on my way"',
  ].join("\n");
}
