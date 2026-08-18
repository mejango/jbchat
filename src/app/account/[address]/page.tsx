import { AccountView } from "@/components/messaging/AccountView";

export const dynamic = "force-dynamic";

export default async function AccountPage({
  params,
}: {
  params: Promise<{ address: string }>;
}) {
  const { address } = await params;
  return <AccountView address={address} />;
}
