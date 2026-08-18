import { createWitnessHttpHandlers } from "@/production/witness/witnessHttp";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const handlers = createWitnessHttpHandlers();

export async function POST(request: Request): Promise<Response> {
  return handlers.reportGossip(request);
}
