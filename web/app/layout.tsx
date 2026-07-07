import type { Metadata } from "next";
import { Playfair_Display, DM_Sans, DM_Mono } from "next/font/google";
import "./globals.css";
import Nav from "@/components/Nav";
import Footer from "@/components/Footer";
import JsonLd from "@/components/JsonLd";
import { localBusinessJsonLd } from "@/lib/seo";
import { SITE_URL, BUSINESS } from "@/lib/site";

const serif = Playfair_Display({
  subsets: ["latin"],
  weight: ["400", "700", "900"],
  style: ["normal", "italic"],
  variable: "--font-serif",
  display: "swap",
});
const sans = DM_Sans({
  subsets: ["latin"],
  weight: ["300", "400", "500", "600"],
  variable: "--font-sans",
  display: "swap",
});
const mono = DM_Mono({
  subsets: ["latin"],
  weight: ["400"],
  variable: "--font-mono",
  display: "swap",
});

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: `${BUSINESS.name} — Walk Your Floor Plans at Full Scale`,
    template: `%s · ${BUSINESS.name}`,
  },
  description:
    "Walk through your home or addition at full scale before construction starts. Metro Detroit floor-plan visualization studio in Troy, MI.",
  alternates: { canonical: "/" },
  openGraph: {
    type: "website",
    siteName: BUSINESS.name,
    locale: "en_US",
  },
  robots: { index: true, follow: true },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${serif.variable} ${sans.variable} ${mono.variable}`}
    >
      <body>
        {/* LocalBusiness JSON-LD on every page (Phase 0 requirement). */}
        <JsonLd data={localBusinessJsonLd()} />
        <Nav />
        <main className="min-h-[60vh]">{children}</main>
        <Footer />
      </body>
    </html>
  );
}
