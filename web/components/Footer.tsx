import Link from "next/link";
import { BUSINESS } from "@/lib/site";

export default function Footer() {
  return (
    <footer className="border-t border-gray-line bg-gray">
      <div className="mx-auto flex max-w-content flex-col gap-4 px-6 py-10 text-[0.78rem] text-ink-lt md:flex-row md:items-center md:justify-between md:px-12">
        <div className="leading-relaxed">
          <span className="font-serif text-[0.95rem] font-bold text-black">
            Walk Your Plans<span className="text-red"> Detroit</span>
          </span>
          <div className="mt-1">
            {BUSINESS.street}, {BUSINESS.city}, {BUSINESS.region}{" "}
            {BUSINESS.postalCode}
          </div>
          <a
            href={`tel:${BUSINESS.phoneE164}`}
            className="transition-colors hover:text-red"
          >
            {BUSINESS.phone}
          </a>
        </div>
        <nav className="flex flex-wrap gap-5">
          <Link href="/builders" className="transition-colors hover:text-red">
            Builders & Architects
          </Link>
          <Link href="/cost/troy" className="transition-colors hover:text-red">
            Pricing
          </Link>
          <Link href="/schedule" className="transition-colors hover:text-red">
            Schedule
          </Link>
        </nav>
      </div>
    </footer>
  );
}
