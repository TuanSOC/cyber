import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { connection } from "next/server";

import { Providers } from "@/components/providers";

import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "CyberLab AI",
  description: "Defensive cybersecurity investigation and analysis platform",
};

// Nonce CSP (see proxy.ts) needs every HTML response rendered per request: Next.js only puts
// the nonce on scripts it renders with the request in hand. Under Cache Components a static
// shell is prerendered at build time, so its bootstrap <script> tags carry no nonce and
// 'strict-dynamic' blocks them all (red-team RT1). Awaiting connection() before <html> means
// nothing is prerendered, for every route including not-found; `instant = false` declares that
// the root is allowed to block (opts the whole app out of static-shell validation).
export const instant = false;

export default async function RootLayout({ children }: LayoutProps<"/">) {
  await connection();
  return (
    <html
      lang="en"
      className={`dark ${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
