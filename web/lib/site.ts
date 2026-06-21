// Single source of truth for business + site constants.

export const SITE_URL =
  process.env.NEXT_PUBLIC_SITE_URL ?? "https://build.walkyourplansdetroit.com";

export const BUSINESS = {
  name: "Walk Your Plans Detroit",
  legalName: "Walk Your Plans Detroit",
  phone: "248-602-0110",
  phoneE164: "+12486020110",
  email: "hello@walkyourplansdetroit.com",
  street: "780 W Maple Road, Suite F",
  city: "Troy",
  region: "MI",
  postalCode: "48084",
  country: "US",
  lat: 42.5523,
  lng: -83.1763,
  tagline: "Walk it before you build it.",
} as const;

// Session price map (display only on content pages — never sent to Stripe from
// the client; Phase 3 validates price server-side from a fixed map).
export const SESSIONS = [
  { hours: 1, priceCents: 85000 },
  { hours: 2, priceCents: 150000 },
  { hours: 3, priceCents: 200000 },
  { hours: 4, priceCents: 250000 },
  { hours: 5, priceCents: 300000 },
] as const;

export function formatUsd(cents: number): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 0,
  }).format(cents / 100);
}
