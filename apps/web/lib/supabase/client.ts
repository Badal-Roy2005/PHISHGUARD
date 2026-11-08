import { createBrowserClient } from "@supabase/ssr";

import { requirePublicEnv } from "../env.ts";
import type { Database } from "./database.types.ts";

export function createClient() {
  return createBrowserClient<Database>(
    requirePublicEnv("NEXT_PUBLIC_SUPABASE_URL"),
    requirePublicEnv("NEXT_PUBLIC_SUPABASE_ANON_KEY"),
  );
}
