import { createMessagingHttpHandlers } from "@/production/http/messagingHttp";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const handlers = createMessagingHttpHandlers();

export async function POST(
  request: Request,
  { params }: { params: Promise<{ conversationId: string }> },
): Promise<Response> {
  return handlers.enableConversationRelay(
    request,
    (await params).conversationId,
  );
}

export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ conversationId: string }> },
): Promise<Response> {
  return handlers.disableConversationRelay(
    request,
    (await params).conversationId,
  );
}
