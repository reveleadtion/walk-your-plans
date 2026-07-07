-- Walk Your Plans Detroit — initial schema (Phase 0)
-- Content tables are public-read; `bookings` is locked (no public policies).
-- Review this migration before applying in the Supabase SQL editor.

-- ─── CONTENT TABLES (public read) ────────────────────────────────────────────

create table if not exists cities (
  id uuid primary key default gen_random_uuid(),
  slug text unique not null,
  name text not null,
  county text,
  intro text,
  lat double precision,
  lng double precision,
  created_at timestamptz default now()
);

create table if not exists home_styles (
  id uuid primary key default gen_random_uuid(),
  slug text unique not null,
  name text not null,
  era text,
  description text,            -- ORIGINAL copy, not a Wikipedia reword
  local_relevance text,        -- Metro Detroit angle (required)
  created_at timestamptz default now()
);

create table if not exists glossary_terms (
  id uuid primary key default gen_random_uuid(),
  slug text unique not null,
  term text not null,
  definition text,
  michigan_note text,          -- code/climate specifics where relevant
  related_slugs text[],
  created_at timestamptz default now()
);

create table if not exists builders (
  id uuid primary key default gen_random_uuid(),
  slug text unique not null,
  name text not null,
  kind text not null check (kind in ('builder','architect')),
  city_id uuid references cities(id),
  website text,
  description text,
  specialties text[],
  created_at timestamptz default now()
);

create table if not exists subdivisions (
  id uuid primary key default gen_random_uuid(),
  slug text unique not null,
  name text not null,
  city_id uuid references cities(id),
  builder_id uuid references builders(id),
  approx_homes int,
  description text,
  created_at timestamptz default now()
);

create table if not exists service_pages (
  id uuid primary key default gen_random_uuid(),
  slug text unique not null,
  city_id uuid references cities(id),
  audience text,               -- homeowner | architect | builder | commercial | null
  page_type text not null,     -- 'service_city' | 'cost' | 'audience'
  h1 text not null,
  body text,
  created_at timestamptz default now()
);

-- ─── TRANSACTIONAL TABLE (locked down) ───────────────────────────────────────

create table if not exists bookings (
  id uuid primary key default gen_random_uuid(),
  name text,
  email text,
  phone text,
  session_length_hours int,
  price_cents int,             -- set SERVER-SIDE only
  stripe_session_id text,
  status text default 'pending',  -- pending | paid | cancelled
  created_at timestamptz default now()
);

-- ─── ROW LEVEL SECURITY ──────────────────────────────────────────────────────

alter table cities          enable row level security;
alter table home_styles     enable row level security;
alter table glossary_terms  enable row level security;
alter table builders        enable row level security;
alter table subdivisions    enable row level security;
alter table service_pages   enable row level security;
alter table bookings        enable row level security;

-- Public read for content tables only.
drop policy if exists "public read" on cities;
create policy "public read" on cities         for select to anon, authenticated using (true);
drop policy if exists "public read" on home_styles;
create policy "public read" on home_styles    for select to anon, authenticated using (true);
drop policy if exists "public read" on glossary_terms;
create policy "public read" on glossary_terms for select to anon, authenticated using (true);
drop policy if exists "public read" on builders;
create policy "public read" on builders       for select to anon, authenticated using (true);
drop policy if exists "public read" on subdivisions;
create policy "public read" on subdivisions   for select to anon, authenticated using (true);
drop policy if exists "public read" on service_pages;
create policy "public read" on service_pages  for select to anon, authenticated using (true);

-- bookings: NO anon/authenticated policies. With RLS enabled and no policy,
-- the anon and authenticated roles can neither read nor write. Writes happen
-- only via server-side route handlers using the service_role key (Phase 3).
