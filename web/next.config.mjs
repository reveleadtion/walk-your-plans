/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // Verbose errors are never sent to the client in production (security rule #7);
  // Next.js already strips stack traces from production responses by default.
};

export default nextConfig;
