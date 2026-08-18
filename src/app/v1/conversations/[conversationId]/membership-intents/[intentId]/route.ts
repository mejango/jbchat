import { createMessagingHttpHandlers } from "@/production/http/messagingHttp";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const handlers = createMessagingHttpHandlers();

export async function DELETE(
  request: Request,
  {
    params,
  }: { params: Promise<{ conversationId: string; intentId: string }> },
): Promise<Response> {
  const resolved = await params;
  return handlers.cancelMembershipIntent(
    request,
    resolved.conversationId,
    resolved.intentId,
  );
}
