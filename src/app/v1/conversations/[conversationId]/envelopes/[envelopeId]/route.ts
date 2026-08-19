import { createMessagingHttpHandlers } from "@/production/http/messagingHttp";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const handlers = createMessagingHttpHandlers();

export async function GET(
  request: Request,
  {
    params,
  }: { params: Promise<{ conversationId: string; envelopeId: string }> },
): Promise<Response> {
  const resolved = await params;
  return handlers.readEnvelope(
    request,
    resolved.conversationId,
    resolved.envelopeId,
  );
}
