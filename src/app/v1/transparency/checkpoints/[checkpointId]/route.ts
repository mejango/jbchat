import { createWitnessHttpHandlers } from "@/production/witness/witnessHttp";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const handlers = createWitnessHttpHandlers();

export async function GET(
  request: Request,
  context: { params: Promise<{ checkpointId: string }> },
): Promise<Response> {
  const { checkpointId } = await context.params;
  return handlers.readCheckpoint(request, checkpointId);
}
