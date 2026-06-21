import type { Metadata } from "next";
import { BUSINESS } from "@/lib/site";
import { canonical } from "@/lib/seo";

// Phase 0 placeholder. The Cal.com embed (Phase 3) and any real booking flow
// land here later. No payment/booking logic ships before the SECURITY GATE.
export const metadata: Metadata = {
  title: "Schedule a Session",
  description:
    "Book a full-scale floor-plan walkthrough at the Walk Your Plans Detroit studio in Troy, MI.",
  alternates: { canonical: canonical("/schedule") },
};

export default function SchedulePage() {
  return (
    <section className="bg-white px-6 py-20 md:px-12 md:py-28">
      <div className="mx-auto max-w-content">
        <p className="eyebrow mb-6">Book your walkthrough</p>
        <h1 className="headline text-[clamp(2rem,3.4vw,3rem)]">
          Schedule a <em>full-scale session</em>
        </h1>
        <p className="mt-6 max-w-xl text-[1rem] leading-relaxed text-ink-mid">
          Online booking is coming to this page. For now, call us at{" "}
          <a
            href={`tel:${BUSINESS.phoneE164}`}
            className="font-semibold text-red"
          >
            {BUSINESS.phone}
          </a>{" "}
          to reserve a session at our Troy studio.
        </p>
        <div className="mt-8 rounded-[10px] border border-dashed border-gray-line bg-gray p-8 text-[0.85rem] text-ink-lt">
          Booking embed placeholder — Cal.com + Stripe arrives in Phase 3, after
          the security checklist passes.
        </div>
      </div>
    </section>
  );
}
