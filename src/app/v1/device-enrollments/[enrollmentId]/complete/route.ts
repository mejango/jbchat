import { createMessagingHttpHandlers } from "@/production/http/messagingHttp";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const handlers = createMessagingHttpHandlers();

export async function POST(
  request: Request,
  { params }: { params: Promise<{ enrollmentId: string }> },
): Promise<Response> {
  return handlers.completeEnrollment(request, (await params).enrollmentId);
}
