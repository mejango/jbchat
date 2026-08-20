import { createMessagingHttpHandlers } from "@/production/http/messagingHttp";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const handlers = createMessagingHttpHandlers();

export async function POST(request: Request): Promise<Response> {
  return handlers.createNotificationChannel(request);
}

export async function GET(request: Request): Promise<Response> {
  return handlers.listNotificationChannels(request);
}
