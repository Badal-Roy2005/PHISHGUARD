const PUBLIC_ENV_NAMES = [
  "NEXT_PUBLIC_SUPABASE_URL",
  "NEXT_PUBLIC_SUPABASE_ANON_KEY",
] as const;

type PublicEnvName = (typeof PUBLIC_ENV_NAMES)[number];

export function requirePublicEnv(name: PublicEnvName): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`${name} is not configured`);
  }
  return value;
}

export function optionalPublicEnv(name: "NEXT_PUBLIC_SITE_URL"): string | undefined {
  const value = process.env[name]?.trim();
  return value || undefined;
}

const _PUBLIC_ENV_NAMES = PUBLIC_ENV_NAMES;