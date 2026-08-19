import type { Metadata } from "next";
import localFont from "next/font/local";
import { connection } from "next/server";
import type { ReactNode } from "react";
import { PwaRegistration } from "@/components/PwaRegistration";
import "./globals.css";
import "./family.css";

const beatrice = localFont({
  src: [
    { path: "../../public/fonts/Beatrice-Regular.woff2", weight: "400" },
    { path: "../../public/fonts/Beatrice-Medium.woff2", weight: "500" },
  ],
  variable: "--font-beatrice",
  display: "swap",
});

const agrandir = localFont({
  src: [{ path: "../../public/fonts/PPAgrandir-Medium.woff2", weight: "500" }],
  variable: "--font-agrandir",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Fruitful",
  description: "Private purchase support and project community messaging.",
  robots: { index: false, follow: false },
};

export default async function RootLayout({
  children,
}: Readonly<{ children: ReactNode }>) {
  await connection();

  return (
    <html lang="en" data-brand="juicebox"
      className={`${beatrice.variable} ${agrandir.variable}`}>
      <body>
        {children}
        <PwaRegistration
          requiresTrustedScriptUrl={
            process.env.JUICEBOX_MESSAGING_WEB_SECURITY_MODE === "production"
          }
        />
      </body>
    </html>
  );
}
