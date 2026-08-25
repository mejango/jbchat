import { describe, expect, it } from "vitest";
import {
  conversationTag,
  renderOutbound,
  renderPrompt,
  routeInbound,
  type RelayEnvelopeContext,
} from "./relayFormat";

const conversationA = "aabbccdd-0000-4000-8000-000000000001";
const conversationB = "eeff0011-0000-4000-8000-000000000002";
const contextOf = (id: string, name: string | null): RelayEnvelopeContext => ({
  projectName: name,
  projectId: "68",
  senderRole: "project-staff",
  tag: conversationTag(id),
});

describe("relay formatting", () => {
  it("renders outbound with tag, project, and sender side", () => {
    expect(
      renderOutbound(
        { projectName: "Banny Retail", projectId: "68", senderRole: "customer", tag: "aabb" },
        "where is my order?",
      ),
    ).toBe("[aabb] Banny Retail — Customer:\nwhere is my order?");
    expect(
      renderOutbound(
        { projectName: null, projectId: "68", senderRole: "project-staff", tag: "aabb" },
        "shipped today",
      ),
    ).toBe("[aabb] Project #68 — Team:\nshipped today");
  });

  it("routes an untagged reply to the only active conversation", () => {
    expect(
      routeInbound("thanks!", [
        { conversationId: conversationA, context: contextOf(conversationA, null) },
      ]),
    ).toEqual({ kind: "send", conversationId: conversationA, text: "thanks!" });
  });

  it("routes a tagged reply to its conversation even among several", () => {
    const conversations = [
      { conversationId: conversationA, context: contextOf(conversationA, "A") },
      { conversationId: conversationB, context: contextOf(conversationB, "B") },
    ];
    expect(routeInbound("[eeff] got it", conversations)).toEqual({
      kind: "send",
      conversationId: conversationB,
      text: "got it",
    });
  });

  it("prompts when several conversations and no tag; never guesses", () => {
    const conversations = [
      { conversationId: conversationA, context: contextOf(conversationA, "A") },
      { conversationId: conversationB, context: contextOf(conversationB, "B") },
    ];
    const routed = routeInbound("hello", conversations);
    expect(routed.kind).toBe("prompt");
    const prompt = renderPrompt(
      conversations.map((candidate) => candidate.context),
    );
    expect(prompt).toContain("[aabb] A");
    expect(prompt).toContain("[eeff] B");
  });

  it("ignores empty messages, bot commands, and no-conversation chats", () => {
    expect(routeInbound("/start abc", [])).toEqual({ kind: "ignore" });
    expect(routeInbound("   ", [])).toEqual({ kind: "ignore" });
    expect(routeInbound("hi", [])).toEqual({ kind: "ignore" });
  });

  it("an unknown tag with one conversation still sends to it verbatim", () => {
    // [9999] doesn't match; single-conversation fallback keeps the text
    // INTACT (the tag might be part of the user's message).
    expect(
      routeInbound("[9999] see attached", [
        { conversationId: conversationA, context: contextOf(conversationA, null) },
      ]),
    ).toEqual({
      kind: "send",
      conversationId: conversationA,
      text: "[9999] see attached",
    });
  });
});
