import type { Metadata } from "next";
import Link from "next/link";
import CtaBand from "@/components/CtaBand";
import JsonLd from "@/components/JsonLd";
import { breadcrumbJsonLd, canonical } from "@/lib/seo";
import { getBuilders, getCities } from "@/lib/data";

export const revalidate = 86400;

export const metadata: Metadata = {
  title: "Metro Detroit Builders & Architects Directory",
  description:
    "A directory of custom home builders and residential architects across Oakland County and Metro Detroit, grouped by city.",
  alternates: { canonical: canonical("/builders") },
  openGraph: {
    title: "Metro Detroit Builders & Architects Directory",
    url: canonical("/builders"),
  },
};

export default async function BuildersIndexPage() {
  const [builders, cities] = await Promise.all([getBuilders(), getCities()]);

  const cityNameBySlug = new Map(cities.map((c) => [c.slug, c.name]));

  // Group builders by city for a faceted directory.
  const byCity = new Map<string, typeof builders>();
  for (const b of builders) {
    const list = byCity.get(b.city_slug) ?? [];
    list.push(b);
    byCity.set(b.city_slug, list);
  }
  const groups = [...byCity.entries()].sort((a, b) =>
    (cityNameBySlug.get(a[0]) ?? a[0]).localeCompare(
      cityNameBySlug.get(b[0]) ?? b[0],
    ),
  );

  return (
    <>
      <JsonLd
        data={breadcrumbJsonLd([
          { name: "Home", path: "/" },
          { name: "Builders & Architects", path: "/builders" },
        ])}
      />

      <section className="border-b border-gray-line bg-white px-6 py-16 md:px-12 md:py-20">
        <div className="mx-auto max-w-content">
          <p className="eyebrow mb-5">Directory</p>
          <h1 className="headline text-[clamp(2rem,3.4vw,3rem)]">
            Metro Detroit <em>builders &amp; architects</em>
          </h1>
          <p className="mt-5 max-w-2xl text-[1rem] leading-relaxed text-ink-mid">
            Custom home builders and residential architects across Oakland
            County. Walking a plan at full scale before framing is the cheapest
            change order you&apos;ll ever make — bring your builder&apos;s
            drawings to our Troy studio and feel the space first.
          </p>
        </div>
      </section>

      <section className="bg-white px-6 pb-16 md:px-12 md:pb-20">
        <div className="mx-auto max-w-content">
          {groups.map(([citySlug, list]) => (
            <div key={citySlug} className="mt-12 first:mt-8">
              <div className="mb-5 flex items-baseline justify-between border-b border-gray-line pb-3">
                <h2 className="font-serif text-[1.4rem] font-bold text-black">
                  {cityNameBySlug.get(citySlug) ?? citySlug}
                </h2>
                <Link
                  href={`/cost/${citySlug}`}
                  className="text-[0.78rem] font-semibold text-red transition-opacity hover:opacity-70"
                >
                  Pricing in {cityNameBySlug.get(citySlug) ?? citySlug} →
                </Link>
              </div>
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                {list.map((b) => (
                  <Link
                    key={b.slug}
                    href={`/builders/${b.slug}`}
                    className="card block p-6"
                  >
                    <div className="font-mono text-[0.58rem] uppercase tracking-[0.1em] text-ink-lt">
                      {b.kind}
                    </div>
                    <div className="mt-2 font-serif text-[1.1rem] font-bold text-black">
                      {b.name}
                    </div>
                    {b.specialties.length > 0 && (
                      <div className="mt-3 flex flex-wrap gap-1.5">
                        {b.specialties.slice(0, 3).map((s) => (
                          <span
                            key={s}
                            className="rounded bg-gray px-2 py-0.5 text-[0.66rem] text-ink-mid"
                          >
                            {s}
                          </span>
                        ))}
                      </div>
                    )}
                  </Link>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      <CtaBand />
    </>
  );
}
