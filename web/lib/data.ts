import "server-only";
import { getSupabaseAnon, supabaseConfigured } from "./supabase/server";
import seed from "@/content/seed.json";

// ─── Types ──────────────────────────────────────────────────────────────────

export type City = {
  slug: string;
  name: string;
  county: string | null;
  intro: string | null;
  lat?: number | null;
  lng?: number | null;
};

export type Builder = {
  slug: string;
  name: string;
  kind: "builder" | "architect";
  city_slug: string;
  website: string | null;
  description: string | null;
  specialties: string[];
};

export type ServicePage = {
  slug: string;
  city_slug: string;
  audience: string | null;
  page_type: string;
  h1: string;
  body: string | null;
};

// ─── Seed fallback ────────────────────────────────────────────────────────────
// Used both for local dev/build before Supabase is wired up and as the source
// of truth for the SQL seed. Reading from it keeps Phase 0 fully renderable.

const seedCities = seed.cities as City[];
const seedBuilders = seed.builders as Builder[];
const seedServicePages = seed.service_pages as ServicePage[];

// ─── Content reads ────────────────────────────────────────────────────────────
// Each reader prefers Supabase when configured and falls back to seed JSON.

export async function getCities(): Promise<City[]> {
  if (supabaseConfigured) {
    const sb = getSupabaseAnon();
    const { data } = await sb!.from("cities").select("*").order("name");
    if (data) return data as City[];
  }
  return [...seedCities].sort((a, b) => a.name.localeCompare(b.name));
}

export async function getCity(slug: string): Promise<City | null> {
  const cities = await getCities();
  return cities.find((c) => c.slug === slug) ?? null;
}

export async function getBuilders(): Promise<Builder[]> {
  if (supabaseConfigured) {
    const sb = getSupabaseAnon();
    // Join through cities to expose the city slug to the directory grouping.
    const { data } = await sb!
      .from("builders")
      .select("slug,name,kind,website,description,specialties,cities(slug)")
      .order("name");
    if (data) {
      return (data as unknown[]).map((row) => {
        const r = row as Record<string, unknown> & {
          cities?: { slug?: string };
        };
        return {
          slug: r.slug as string,
          name: r.name as string,
          kind: r.kind as Builder["kind"],
          city_slug: r.cities?.slug ?? "",
          website: (r.website as string) ?? null,
          description: (r.description as string) ?? null,
          specialties: (r.specialties as string[]) ?? [],
        };
      });
    }
  }
  return [...seedBuilders].sort((a, b) => a.name.localeCompare(b.name));
}

export async function getBuilder(slug: string): Promise<Builder | null> {
  const builders = await getBuilders();
  return builders.find((b) => b.slug === slug) ?? null;
}

export async function getServicePages(): Promise<ServicePage[]> {
  if (supabaseConfigured) {
    const sb = getSupabaseAnon();
    const { data } = await sb!
      .from("service_pages")
      .select("slug,audience,page_type,h1,body,cities(slug)")
      .eq("page_type", "cost");
    if (data) {
      return (data as unknown[]).map((row) => {
        const r = row as Record<string, unknown> & {
          cities?: { slug?: string };
        };
        return {
          slug: r.slug as string,
          city_slug: r.cities?.slug ?? (r.slug as string),
          audience: (r.audience as string) ?? null,
          page_type: r.page_type as string,
          h1: r.h1 as string,
          body: (r.body as string) ?? null,
        };
      });
    }
  }
  return seedServicePages;
}

export async function getCostPage(citySlug: string): Promise<ServicePage | null> {
  const pages = await getServicePages();
  return (
    pages.find((p) => p.page_type === "cost" && p.city_slug === citySlug) ?? null
  );
}
