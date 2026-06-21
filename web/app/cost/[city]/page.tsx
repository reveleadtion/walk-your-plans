import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import CtaBand from "@/components/CtaBand";
import JsonLd from "@/components/JsonLd";
import { breadcrumbJsonLd, canonical } from "@/lib/seo";
import { getCities, getCity, getCostPage, getBuilders } from "@/lib/data";
import { SESSIONS, formatUsd, BUSINESS } from "@/lib/site";

export const revalidate = 86400;

// One cost page per city. generateStaticParams covers every seeded city so the
// route renders even where no custom service_pages row exists yet.
export async function generateStaticParams() {
  const cities = await getCities();
  return cities.map((c) => ({ city: c.slug }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ city: string }>;
}): Promise<Metadata> {
  const { city: citySlug } = await params;
  const city = await getCity(citySlug);
  if (!city) return { title: "Not found" };

  const page = await getCostPage(citySlug);
  const title =
    page?.h1 ?? `Floor-Plan Walkthrough Cost in ${city.name}, MI`;
  return {
    title,
    description: `Session pricing for a full-scale floor-plan walkthrough serving ${city.name}, ${city.county ?? "Metro Detroit"}. Sessions from ${formatUsd(SESSIONS[0].priceCents)}.`,
    alternates: { canonical: canonical(`/cost/${city.slug}`) },
    openGraph: { title, url: canonical(`/cost/${city.slug}`) },
  };
}

export default async function CostPage({
  params,
}: {
  params: Promise<{ city: string }>;
}) {
  const { city: citySlug } = await params;
  const city = await getCity(citySlug);
  if (!city) notFound();

  const [page, builders] = await Promise.all([
    getCostPage(citySlug),
    getBuilders(),
  ]);
  const cityBuilders = builders
    .filter((b) => b.city_slug === citySlug)
    .slice(0, 4);

  const h1 = page?.h1 ?? `Floor-Plan Walkthrough Cost in ${city.name}, MI`;

  return (
    <>
      <JsonLd
        data={[
          breadcrumbJsonLd([
            { name: "Home", path: "/" },
            { name: `${city.name} Pricing`, path: `/cost/${city.slug}` },
          ]),
          {
            "@context": "https://schema.org",
            "@type": "Service",
            serviceType: "Full-scale floor-plan visualization",
            provider: { "@id": `${canonical("/")}#business` },
            areaServed: `${city.name}, MI`,
            offers: SESSIONS.map((s) => ({
              "@type": "Offer",
              name: `${s.hours}-hour session`,
              price: (s.priceCents / 100).toFixed(2),
              priceCurrency: "USD",
            })),
          },
        ]}
      />

      <section className="border-b border-gray-line bg-white px-6 py-16 md:px-12 md:py-20">
        <div className="mx-auto max-w-content">
          <p className="eyebrow mb-4">
            Pricing · {city.name}, {city.county ?? "Metro Detroit"}
          </p>
          <h1 className="headline text-[clamp(2rem,3.4vw,3rem)]">{h1}</h1>
          {city.intro && (
            <p className="mt-6 max-w-2xl text-[1rem] leading-relaxed text-ink-mid">
              {city.intro}
            </p>
          )}
        </div>
      </section>

      {/* Price table */}
      <section className="bg-gray px-6 py-14 md:px-12 md:py-16">
        <div className="mx-auto max-w-content">
          <h2 className="font-serif text-[1.5rem] font-bold text-black">
            Session pricing
          </h2>
          <div className="mt-6 grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
            {SESSIONS.map((s) => (
              <div key={s.hours} className="card p-6 text-center">
                <div className="font-mono text-[0.62rem] uppercase tracking-[0.1em] text-ink-lt">
                  {s.hours} hour{s.hours > 1 ? "s" : ""}
                </div>
                <div className="mt-2 font-serif text-[1.7rem] font-black text-red">
                  {formatUsd(s.priceCents)}
                </div>
              </div>
            ))}
          </div>
          <p className="mt-4 text-[0.75rem] italic text-ink-lt">
            Prices shown for reference. Final price is confirmed at booking.
          </p>
        </div>
      </section>

      {page?.body && (
        <section className="bg-white px-6 py-14 md:px-12 md:py-16">
          <div className="mx-auto max-w-content">
            <div className="max-w-2xl whitespace-pre-line text-[0.98rem] leading-relaxed text-ink-mid">
              {page.body}
            </div>
          </div>
        </section>
      )}

      {/* Two-tier interlink: cost page (money) → builders (traffic). */}
      {cityBuilders.length > 0 && (
        <section className="bg-white px-6 pb-14 md:px-12 md:pb-16">
          <div className="mx-auto max-w-content">
            <h2 className="font-serif text-[1.4rem] font-bold text-black">
              Builders &amp; architects in {city.name}
            </h2>
            <div className="mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              {cityBuilders.map((b) => (
                <Link
                  key={b.slug}
                  href={`/builders/${b.slug}`}
                  className="card block p-5"
                >
                  <div className="font-mono text-[0.56rem] uppercase tracking-[0.1em] text-ink-lt">
                    {b.kind}
                  </div>
                  <div className="mt-1.5 font-serif text-[1rem] font-bold text-black">
                    {b.name}
                  </div>
                </Link>
              ))}
            </div>
            <Link
              href="/builders"
              className="mt-5 inline-block text-[0.85rem] font-semibold text-red transition-opacity hover:opacity-70"
            >
              See the full directory →
            </Link>
          </div>
        </section>
      )}

      <CtaBand
        heading={`Walk your ${city.name} plans before you build.`}
        sub={`Book a full-scale session at our Troy studio, ${BUSINESS.street}. Most ${city.name} plans surface 10–12 fixable issues.`}
      />
    </>
  );
}
