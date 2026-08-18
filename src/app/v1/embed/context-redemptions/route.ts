import { createEmbedBffHandlers } from "@/production/embed/embedBff";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const handlers = createEmbedBffHandlers();

export async function POST(request: Request): Promise<Response> {
  return handlers.redeemContext(request);
}
