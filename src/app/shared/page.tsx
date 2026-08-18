import { notFound } from "next/navigation";
import type { Metadata } from "next";
import { SharedMessagingApp } from "@/shared/SharedMessagingApp";

export const metadata: Metadata = {
  title: "Shared HTTP LAN messaging test",
  description:
    "Development-only cross-device messaging with simulated payloads. This HTTP LAN test is not end-to-end encrypted.",
};

export default function SharedPage() {
  if (process.env.JUICEBOX_MESSAGING_WEB_SECURITY_MODE === "production") {
    notFound();
  }
  return <SharedMessagingApp />;
}
