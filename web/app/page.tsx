import Link from "next/link";
import CtaBand from "@/components/CtaBand";
import { getCities } from "@/lib/data";
import { SESSIONS, formatUsd } from "@/lib/site";

export const revalidate = 86400;

export default async function HomePage() {
  const cities = await getCities();

  return (
    <>
      {/* Hero — light background, serif headline with italic-red emphasis. */}
      <section className="border-b border-gray-line bg-white px-6 py-20 md:px-12 md:py-28">
        <div className="mx-auto max-w-content">
          <p className="eyebrow mb-6">Metro Detroit · Troy, MI</p>
          <h1 className="headline max-w-3xl text-[clamp(2.4rem,4.4vw,3.9rem)]">
            See your floor plan at <em>full scale</em> before a single wall goes
            up.
          </h1>
          <p className="mt-6 max-w-xl text-[1.02rem] leading-relaxed text-ink-mid">
            We tape out your home, addition, or outdoor space at 1:1 in our Troy
            studio so you can walk it, feel the volume, and catch the costly
            change orders while they&apos;re still lines on a page. A typical
            session surfaces 10–12 fixable issues — about $10.8K in avoided
            change orders.
          </p>
          <div className="mt-9 flex flex-wrap gap-4">
            <Link href="/schedule" className="btn-primary">
              Book a Session
            </Link>
            <Link href="/cost/troy" className="btn-ghost">
              See Pricing
            </Link>
          </div>
        </div>
      </section>

      {/* Pricing snapshot */}
      <section className="bg-gray px-6 py-16 md:px-12 md:py-20">
        <div className="mx-auto max-w-content">
          <p className="eyebrow mb-4">By the hour</p>
          <h2 className="headline text-[clamp(1.7rem,2.6vw,2.4rem)]">
            Sessions at our <em>Troy studio</em>
          </h2>
          <div className="mt-8 grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
            {SESSIONS.map((s) => (
              <div key={s.hours} className="card p-6 text-center">
                <div className="font-mono text-[0.62rem] uppercase tracking-[0.1em] text-ink-lt">
                  {s.hours} hour{s.hours > 1 ? "s" : ""}
                </div>
                <div className="mt-2 font-serif text-[1.8rem] font-black text-red">
                  {formatUsd(s.priceCents)}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Service-area cities → cost pages (two-tier interlink seed) */}
      <section className="bg-white px-6 py-16 md:px-12 md:py-20">
        <div className="mx-auto max-w-content">
          <p className="eyebrow mb-4">Service area</p>
          <h2 className="headline text-[clamp(1.7rem,2.6vw,2.4rem)]">
            Serving <em>Oakland County</em> &amp; Metro Detroit
          </h2>
          <div className="mt-8 flex flex-wrap gap-3">
            {cities.map((c) => (
              <Link
                key={c.slug}
                href={`/cost/${c.slug}`}
                className="rounded border border-gray-line px-4 py-2 text-[0.85rem] font-medium text-ink-mid transition-colors hover:border-red hover:text-black"
              >
                {c.name}
              </Link>
            ))}
            <Link
              href="/builders"
              className="rounded border border-gray-line px-4 py-2 text-[0.85rem] font-medium text-ink-mid transition-colors hover:border-red hover:text-black"
            >
              Builders &amp; Architects →
            </Link>
          </div>
        </div>
      </section>

      <CtaBand />
    </>
  );
}
