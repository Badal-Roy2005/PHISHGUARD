import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // The contracts package ships TypeScript source; Next compiles it in place.
  transpilePackages: ["@phishguard/contracts"],
  poweredByHeader: false,
};

export default nextConfig;
