import Link from "next/link";
import { BUSINESS } from "@/lib/site";

// Reusable conversion band. Every content page ends with a clear CTA to
// /schedule (Phase 0 requirement). Red surface for emphasis on the light site.
export default function CtaBand({
  heading = "Walk it before you build it.",
  sub = "Book a full-scale session at our Troy studio and catch the costly issues while they're still lines on a page.",
}: {
  heading?: string;
  sub?: string;
}) {
  return (
    <section className="bg-red px-6 py-16 md:px-12 md:py-20">
      <div className="mx-auto max-w-2xl text-center">
        <h2 className="font-serif text-[clamp(1.8rem,3.4vw,2.8rem)] font-black leading-[1.1] text-white">
          {heading}
        </h2>
        <p className="mx-auto mt-4 max-w-md text-[0.94rem] leading-relaxed text-white/80">
          {sub}
        </p>
        <div className="mt-8 flex flex-wrap justify-center gap-4">
          <Link
            href="/schedule"
            className="inline-flex items-center gap-2 rounded border-2 border-white bg-white px-9 py-4 text-[0.9rem] font-bold text-red transition-colors hover:bg-transparent hover:text-white"
          >
            Book a Session
          </Link>
          <a
            href={`tel:${BUSINESS.phoneE164}`}
            className="inline-flex items-center gap-2 rounded border border-white/45 px-9 py-4 text-[0.9rem] font-medium text-white transition-colors hover:border-white hover:bg-white/10"
          >
            Call {BUSINESS.phone}
          </a>
        </div>
      </div>
    </section>
  );
}
