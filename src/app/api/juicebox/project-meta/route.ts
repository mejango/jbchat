import { BendystrawDiscoveryAdapter } from "@/integrations/juicebox/discovery.server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const KEY = /^([1-9]\d{0,9}):([1-9]\d{0,9})$/;

/** Name/logo for a set of projects: ?keys=8453:68,1:12 (public chain data). */
export async function GET(request: Request): Promise<Response> {
  const raw = new URL(request.url).searchParams.get("keys") ?? "";
  const items = raw
    .split(",")
    .map((key) => key.trim().match(KEY))
    .filter((match): match is RegExpMatchArray => match !== null)
    .map((match) => ({
      chainId: Number(match[1]),
      projectId: Number(match[2]),
    }));
  if (items.length === 0) return Response.json({});
  try {
    const meta = await new BendystrawDiscoveryAdapter().projectMeta(items);
    return Response.json(meta, {
      headers: { "Cache-Control": "public, max-age=300" },
    });
  } catch {
    return Response.json({}, { status: 200 });
  }
}
