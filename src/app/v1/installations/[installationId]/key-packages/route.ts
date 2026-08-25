import { createMessagingHttpHandlers } from "@/production/http/messagingHttp";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const handlers = createMessagingHttpHandlers();

export async function POST(
  request: Request,
  { params }: { params: Promise<{ installationId: string }> },
): Promise<Response> {
  return handlers.publishKeyPackages(request, (await params).installationId);
}

export async function GET(
  request: Request,
  { params }: { params: Promise<{ installationId: string }> },
): Promise<Response> {
  return handlers.readKeyPackageShelf(request, (await params).installationId);
}
