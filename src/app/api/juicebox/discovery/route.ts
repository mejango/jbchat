import { BendystrawDiscoveryAdapter } from "@/integrations/juicebox/discovery.server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

export async function GET(request: Request): Promise<Response> {
  const address = new URL(request.url).searchParams.get("address") ?? "";
  if (!ADDRESS.test(address)) {
    return Response.json({ error: "invalid_address" }, { status: 400 });
  }
  try {
    const discovery = await new BendystrawDiscoveryAdapter().discover(address);
    return Response.json(discovery, {
      headers: { "Cache-Control": "no-store" },
    });
  } catch {
    return Response.json({ asCustomer: [], asOwner: [] }, { status: 200 });
  }
}
