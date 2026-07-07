import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import CtaBand from "@/components/CtaBand";
import JsonLd from "@/components/JsonLd";
import { breadcrumbJsonLd, canonical } from "@/lib/seo";
import { getBuilder, getBuilders, getCity } from "@/lib/data";

export const revalidate = 86400;

export async function generateStaticParams() {
  const builders = await getBuilders();
  return builders.map((b) => ({ slug: b.slug }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ slug: string }>;
}): Promise<Metadata> {
  const { slug } = await params;
  const builder = await getBuilder(slug);
  if (!builder) return { title: "Not found" };

  const city = await getCity(builder.city_slug);
  const kind = builder.kind === "architect" ? "Architect" : "Home Builder";
  const where = city ? ` in ${city.name}, MI` : " in Metro Detroit";
  return {
    title: `${builder.name} — ${kind}${where}`,
    description:
      builder.description ??
      `${builder.name}, a ${builder.kind}${where}. Walk your plans at full scale before you build with Walk Your Plans Detroit.`,
    alternates: { canonical: canonical(`/builders/${builder.slug}`) },
    openGraph: {
      title: `${builder.name} — ${kind}${where}`,
      url: canonical(`/builders/${builder.slug}`),
    },
  };
}

export default async function BuilderDetailPage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const builder = await getBuilder(slug);
  if (!builder) notFound();

  const city = await getCity(builder.city_slug);
  const cityName = city?.name ?? "Metro Detroit";

  return (
    <>
      <JsonLd
        data={[
          breadcrumbJsonLd([
            { name: "Home", path: "/" },
            { name: "Builders & Architects", path: "/builders" },
            { name: builder.name, path: `/builders/${builder.slug}` },
          ]),
          {
            "@context": "https://schema.org",
            "@type":
              builder.kind === "architect"
                ? "ProfessionalService"
                : "GeneralContractor",
            name: builder.name,
            url: builder.website ?? undefined,
            areaServed: cityName,
            address: city
              ? {
                  "@type": "PostalAddress",
                  addressLocality: city.name,
                  addressRegion: "MI",
                  addressCountry: "US",
                }
              : undefined,
          },
        ]}
      />

      <section className="border-b border-gray-line bg-white px-6 py-16 md:px-12 md:py-20">
        <div className="mx-auto max-w-content">
          <nav className="mb-6 text-[0.78rem] text-ink-lt">
            <Link href="/builders" className="transition-colors hover:text-red">
              Builders &amp; Architects
            </Link>
            <span className="px-2">/</span>
            <span>{builder.name}</span>
          </nav>
          <p className="eyebrow mb-4">
            {builder.kind} · {cityName}, MI
          </p>
          <h1 className="headline text-[clamp(2rem,3.4vw,3rem)]">
            {builder.name}
          </h1>
          {builder.description && (
            <p className="mt-6 max-w-2xl text-[1rem] leading-relaxed text-ink-mid">
              {builder.description}
            </p>
          )}

          {builder.specialties.length > 0 && (
            <div className="mt-6 flex flex-wrap gap-2">
              {builder.specialties.map((s) => (
                <span
                  key={s}
                  className="rounded bg-gray px-3 py-1 text-[0.72rem] text-ink-mid"
                >
                  {s}
                </span>
              ))}
            </div>
          )}

          {builder.website && (
            <a
              href={builder.website}
              rel="nofollow noopener"
              target="_blank"
              className="mt-6 inline-block text-[0.85rem] font-semibold text-red transition-opacity hover:opacity-70"
            >
              Visit website →
            </a>
          )}

          {/* Two-tier interlink: builder (traffic) → cost page (money). */}
          <div className="mt-10 rounded-[10px] border border-gray-line bg-gray p-6">
            <p className="text-[0.9rem] text-ink-mid">
              Building or renovating in {cityName}? See{" "}
              <Link
                href={`/cost/${builder.city_slug}`}
                className="font-semibold text-red"
              >
                what a full-scale walkthrough costs in {cityName}
              </Link>{" "}
              — then bring {builder.name}&apos;s plans to our Troy studio before
              framing.
            </p>
          </div>
        </div>
      </section>

      <CtaBand />
    </>
  );
}
