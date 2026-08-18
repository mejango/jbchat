import { createMessagingHttpHandlers } from "@/production/http/messagingHttp";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const handlers = createMessagingHttpHandlers();

export async function PUT(
  request: Request,
  {
    params,
  }: { params: Promise<{ installationId: string; endpointId: string }> },
): Promise<Response> {
  const resolved = await params;
  return handlers.registerPushEndpoint(
    request,
    resolved.installationId,
    resolved.endpointId,
  );
}

export async function DELETE(
  request: Request,
  {
    params,
  }: { params: Promise<{ installationId: string; endpointId: string }> },
): Promise<Response> {
  const resolved = await params;
  return handlers.deletePushEndpoint(
    request,
    resolved.installationId,
    resolved.endpointId,
  );
}
