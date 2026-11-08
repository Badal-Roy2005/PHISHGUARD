import type { Metadata } from "next";

import "./globals.css";

export const metadata: Metadata = {
  title: "PHISHGUARD",
  description: "Trust the link. Verify the destination.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}
