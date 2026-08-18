import type { Metadata } from "next";
import { headers } from "next/headers";
import { notFound } from "next/navigation";
import { EmbedProductionFrame } from "@/embed/EmbedProductionFrame";
import { loadWebSecurityConfig } from "@/server/security/config";
import { parseOwnedStylesheetNonce } from "@/theme/ownedStylesheet";

export const metadata: Metadata = {
  title: "Juicebox secure messaging",
  description:
    "Tenant-bound secure messaging frame for registered host applications.",
  robots: { index: false, follow: false },
};

/**
 * Production tenant frame document. Authority comes only from build/runtime
 * configuration: an unconfigured mode, unknown tenant, or query-bearing
 * request stays the class-based 404, exactly like the pre-implementation
 * launch gate; a configured tenant renders the fail-closed frame whose
 * context redemption still requires the live embed context plane.
 */
export default async function EmbedTenantFramePage({
  params,
  searchParams,
}: {
  params: Promise<{ tenantPublicId: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const config = loadWebSecurityConfig(process.env);
  if (config.mode !== "production") notFound();
  const { tenantPublicId } = await params;
  const integration = config.embedIntegrations.find(
    (candidate) => candidate.tenantPublicId === tenantPublicId,
  );
  if (!integration) notFound();
  if (Object.keys(await searchParams).length > 0) notFound();
  const nonce = parseOwnedStylesheetNonce((await headers()).get("x-nonce"));
  return (
    <EmbedProductionFrame
      allowedParentOrigins={integration.frameAncestors}
      stylesheetNonce={nonce ?? undefined}
    />
  );
}
