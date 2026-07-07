import type { MetadataRoute } from "next";
import { SITE_URL } from "@/lib/site";
import { getBuilders, getCities } from "@/lib/data";

// Dynamic sitemap built from DB/seed rows.
export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const [cities, builders] = await Promise.all([getCities(), getBuilders()]);
  const now = new Date();

  const staticRoutes: MetadataRoute.Sitemap = [
    { url: `${SITE_URL}/`, lastModified: now, changeFrequency: "weekly", priority: 1 },
    { url: `${SITE_URL}/builders`, lastModified: now, changeFrequency: "weekly", priority: 0.8 },
    { url: `${SITE_URL}/schedule`, lastModified: now, changeFrequency: "monthly", priority: 0.9 },
  ];

  const cityRoutes: MetadataRoute.Sitemap = cities.map((c) => ({
    url: `${SITE_URL}/cost/${c.slug}`,
    lastModified: now,
    changeFrequency: "monthly",
    priority: 0.7,
  }));

  const builderRoutes: MetadataRoute.Sitemap = builders.map((b) => ({
    url: `${SITE_URL}/builders/${b.slug}`,
    lastModified: now,
    changeFrequency: "monthly",
    priority: 0.6,
  }));

  return [...staticRoutes, ...cityRoutes, ...builderRoutes];
}
