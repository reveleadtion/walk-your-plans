import "server-only";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";

// SERVER-ONLY Supabase clients.
//
// The `import "server-only"` guard makes the build fail if any of this is ever
// pulled into a Client Component, which keeps the service_role key off the
// browser (security rule #1).

const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

// True once the public Supabase env vars exist. When false, the data layer
// falls back to the committed seed JSON so the pitch artifact still renders.
export const supabaseConfigured = Boolean(url && anonKey);

// Anon client — used for public, RLS-protected content reads.
export function getSupabaseAnon(): SupabaseClient | null {
  if (!url || !anonKey) return null;
  return createClient(url, anonKey, {
    auth: { persistSession: false },
  });
}

// Service-role client — bypasses RLS. ONLY for trusted server code (e.g. the
// bookings route handlers in Phase 3 and the content seed script). Never import
// this into anything that reaches the browser.
export function getSupabaseAdmin(): SupabaseClient | null {
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !serviceKey) return null;
  return createClient(url, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}
