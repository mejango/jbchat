import { createMessagingHttpHandlers } from "@/production/http/messagingHttp";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const handlers = createMessagingHttpHandlers();

export async function POST(
  request: Request,
  { params }: { params: Promise<{ projectRefId: string }> },
): Promise<Response> {
  return handlers.registerProjectStaff(request, (await params).projectRefId);
}
