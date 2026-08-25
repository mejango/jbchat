import { createMessagingHttpHandlers } from "@/production/http/messagingHttp";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const handlers = createMessagingHttpHandlers();

export async function GET(request: Request): Promise<Response> {
  return handlers.listInstallations(request);
}
