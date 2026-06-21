-- Walk Your Plans Detroit — Phase 0 seed (one Oakland County cluster).
-- Mirrors web/content/seed.json. Placeholder copy with an original local angle;
-- replace with finalized first-party content. Run after 0001_init.sql.

-- ─── Cities ──────────────────────────────────────────────────────────────────
insert into cities (slug, name, county, lat, lng, intro) values
('troy','Troy','Oakland',42.6064,-83.1498,'Troy homeowners build big on deep Beverly Hills- and Sylvan Glen-adjacent lots, which is exactly where a full-scale walkthrough pays off: we tape out the real footprint in our Troy studio so you feel a 14-foot great room before the trusses are ordered. Most Troy plans we walk surface 10–12 fixable issues — island clearances, mudroom drop-zones off a three-car garage, primary-suite sightlines — at a typical catch value around $10.8K.'),
('bloomfield-hills','Bloomfield Hills','Oakland',42.5837,-83.2455,'Bloomfield Hills projects tend toward larger custom homes and additions where ceiling volume and gallery-style circulation matter as much as square footage. Walking the plan at 1:1 before framing is how our Bloomfield Hills clients confirm a two-story foyer reads grand and not cavernous — and catch the change orders that quietly add up on a high-finish build.'),
('birmingham','Birmingham','Oakland',42.5467,-83.2113,'Birmingham''s tighter in-town lots and teardown-rebuilds make every foot count. We walk Birmingham plans to pressure-test narrow stair runs, second-floor laundry placement, and how a kitchen opens to a smaller back-yard footprint — the spatial trade-offs that don''t show up on a 2D sheet until the walls are already up.'),
('rochester-hills','Rochester Hills','Oakland',42.6584,-83.1499,'Rochester Hills families build for the long haul — open kitchens, finished basements, and flex rooms that change use over a decade. Walking the plan full-scale is how they confirm furniture actually fits and traffic flows before a single Michigan-basement footing is poured.'),
('royal-oak','Royal Oak','Oakland',42.4895,-83.1446,'Royal Oak''s bungalow lots and second-story additions live or die on circulation. We tape out Royal Oak plans so owners feel how a pop-top stair lands, whether the new primary suite clears the existing roofline, and how an addition meets the original 1940s footprint — before demo day.'),
('northville','Northville','Wayne / Oakland (split)',42.4311,-83.4833,'Northville straddles the Wayne–Oakland county line, and its mix of historic-district lots and newer subdivisions means code and setback specifics vary block to block. We walk Northville plans at full scale to confirm a renovation respects the streetscale while the inside lives the way the family actually moves through it.'),
('novi','Novi','Oakland',42.4806,-83.4755,'Novi''s newer subdivisions favor large open plans where the risk isn''t fit, it''s feel — a great room that photographs huge but seats poorly. Walking the Novi plan 1:1 settles island length, sightlines to the back yard, and whether the bonus room earns its stair before the builder locks the spec.')
on conflict (slug) do nothing;

-- ─── Builders & architects ───────────────────────────────────────────────────
insert into builders (slug, name, kind, city_id, website, description, specialties)
select v.slug, v.name, v.kind, c.id, v.website, v.description, v.specialties
from (values
  ('maple-ridge-custom-homes','Maple Ridge Custom Homes','builder','troy','https://example.com','Placeholder Troy-based custom builder focused on 3,500–6,000 sq ft new construction across Oakland County. Replace with the real partner profile.', array['new construction','custom homes','additions']),
  ('woodward-design-build','Woodward Design Build','builder','birmingham','https://example.com','Placeholder Birmingham design-build firm specializing in in-town teardown-rebuilds and second-story additions. Replace with the real partner profile.', array['design-build','teardown-rebuild','additions']),
  ('hill-country-architects','Hill Country Architects','architect','bloomfield-hills','https://example.com','Placeholder residential architecture studio working on high-finish custom homes in Bloomfield Hills and Birmingham. Replace with the real partner profile.', array['residential architecture','custom homes']),
  ('rochester-built','Rochester Built','builder','rochester-hills','https://example.com','Placeholder Rochester Hills production-plus-custom builder. Family-focused open plans with finished Michigan basements. Replace with the real partner profile.', array['custom homes','basements','open plans']),
  ('oakline-studio','Oakline Studio','architect','royal-oak','https://example.com','Placeholder Royal Oak architecture studio specializing in bungalow pop-tops and modern infill. Replace with the real partner profile.', array['additions','infill','renovation']),
  ('north-line-builders','North Line Builders','builder','northville','https://example.com','Placeholder Northville builder working both sides of the Wayne–Oakland line, from historic-district renovations to new subdivision homes. Replace with the real partner profile.', array['new construction','renovation','historic district']),
  ('novi-craft-homes','Novi Craft Homes','builder','novi','https://example.com','Placeholder Novi builder focused on large open-plan new construction in newer subdivisions. Replace with the real partner profile.', array['new construction','open plans']),
  ('meridian-architecture','Meridian Architecture','architect','troy','https://example.com','Placeholder Troy residential + light-commercial architecture practice. Replace with the real partner profile.', array['residential architecture','commercial','additions']),
  ('great-lakes-design-group','Great Lakes Design Group','architect','rochester-hills','https://example.com','Placeholder Rochester Hills architecture group working across Oakland and Macomb counties. Replace with the real partner profile.', array['residential architecture','custom homes']),
  ('birmingham-fine-homes','Birmingham Fine Homes','builder','birmingham','https://example.com','Placeholder high-finish custom builder serving Birmingham and Bloomfield Hills. Replace with the real partner profile.', array['custom homes','high finish','renovation'])
) as v(slug, name, kind, city_slug, website, description, specialties)
join cities c on c.slug = v.city_slug
on conflict (slug) do nothing;

-- ─── Service page (one Troy cost page) ───────────────────────────────────────
insert into service_pages (slug, city_id, audience, page_type, h1, body)
select 'troy', c.id, 'homeowner', 'cost',
  'What a Floor-Plan Walkthrough Costs in Troy, MI',
  'Walk Your Plans Detroit sessions are priced by the hour at our Troy studio on W Maple Road: 1 hour is $850, 2 hours $1,500, 3 hours $2,000, 4 hours $2,500, and 5 hours $3,000. Most Troy single-family plans are well-served by a 2-hour session — long enough to tape out the main level at full scale, walk the kitchen and primary suite, and pressure-test circulation. Larger custom homes and whole-house renovations usually book 3 hours. The math that matters: a typical walkthrough surfaces 10–12 fixable issues, and clients tell us the average catch is worth about $10.8K in avoided change orders — so a $1,500 session routinely pays for itself several times over before the first wall goes up. This is original placeholder copy with Troy-specific session guidance; replace the exact figures and examples with finalized first-party data.'
from cities c where c.slug = 'troy'
on conflict (slug) do nothing;
