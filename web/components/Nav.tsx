import Link from "next/link";
import { BUSINESS } from "@/lib/site";

// Light-theme top nav (the build site is calmer/lighter than the dark landing
// page). Server component — no interactivity needed here.
export default function Nav() {
  return (
    <header className="sticky top-0 z-50 border-b border-gray-line bg-white/95 backdrop-blur">
      <nav className="mx-auto flex h-[68px] max-w-content items-center justify-between px-6 md:px-12">
        <Link href="/" className="flex items-center gap-3">
          <span className="font-serif text-[1.05rem] font-bold leading-tight text-black">
            Walk Your Plans<span className="text-red"> Detroit</span>
          </span>
        </Link>

        <div className="flex items-center gap-5 md:gap-7">
          <Link
            href="/builders"
            className="hidden text-[0.8rem] font-medium uppercase tracking-[0.05em] text-ink-mid transition-colors hover:text-black sm:block"
          >
            Builders
          </Link>
          <Link
            href="/cost/troy"
            className="hidden text-[0.8rem] font-medium uppercase tracking-[0.05em] text-ink-mid transition-colors hover:text-black sm:block"
          >
            Pricing
          </Link>
          <a
            href={`tel:${BUSINESS.phoneE164}`}
            className="hidden text-[0.8rem] font-medium text-ink-mid transition-colors hover:text-black md:block"
          >
            {BUSINESS.phone}
          </a>
          <Link href="/schedule" className="btn-primary !px-5 !py-2.5">
            Book a Session
          </Link>
        </div>
      </nav>
    </header>
  );
}
