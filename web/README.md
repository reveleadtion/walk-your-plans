# Walk Your Plans Detroit — Build Site (Phase 0)

Custom Next.js + Supabase site for `build.walkyourplansdetroit.com`. Phase 0 is
the **pitch artifact**: a live subdomain with a working template and real pages
rendered from Supabase content tables. Read-only, zero payment/booking risk.

Light background (white/gray) with the brand red accent and serif headlines —
calmer than the dark `go.` landing page.

## Stack
- Next.js 15 (App Router, TypeScript, RSC) · Tailwind CSS
- Supabase (Postgres) — content public-read via RLS; `bookings` locked
- Hosting: Vercel

## Getting started
```bash
cd web
npm install
cp .env.example .env.local   # fill in Supabase keys (optional for local render)
npm run dev
```

Without Supabase env vars the data layer falls back to `content/seed.json`, so
every page still renders locally and on Vercel.

## Database
1. Run `supabase/migrations/0001_init.sql` in the Supabase SQL editor (review first).
2. Run `supabase/seed.sql` to load the Oakland County cluster.
3. RLS: content tables are public-read; `bookings` has **no** public policy.

## Routes (Phase 0)
- `/` — home
- `/builders` — directory index, grouped by city
- `/builders/[slug]` — builder/architect detail
- `/cost/[city]` — per-city pricing (money page)
- `/schedule` — placeholder (Cal.com + Stripe arrive in Phase 3, after the security gate)
- `/sitemap.xml`, `/robots.txt`

## Security notes
- `service_role` key is server-only (`lib/supabase/server.ts` is `server-only`).
- Only `NEXT_PUBLIC_*` vars reach the browser.
- No real keys committed; `.env*` is gitignored.

## Deploy (Vercel)
Set the project **Root Directory** to `web/`. Add env vars from `.env.example`.
Run `npm audit` before deploy; fix high/critical. Point the
`build.walkyourplansdetroit.com` subdomain at the deployment.
