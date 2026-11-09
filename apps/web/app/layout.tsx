import type { Metadata } from "next";

import "./globals.css";

import { createClient } from "@/lib/supabase/server";
import Navbar from "@/components/Navbar";

export const metadata: Metadata = {
  title: "PHISHGUARD",
  description: "Trust the link. Verify the destination.",
};

export default async function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

  return (
    <html lang="en">
      <body className="min-h-screen antialiased bg-slate-950 text-slate-100">
        <Navbar user={user} />
        <main>{children}</main>
      </body>
    </html>
  );
}
