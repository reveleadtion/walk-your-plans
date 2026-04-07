const crypto = require("crypto");
const { hash } = require("../lib/hash");

// ── Config ────────────────────────────────────────────────────────────────────
const PIXEL_ID  = process.env.META_PIXEL_ID;
const API_TOKEN = process.env.META_API_TOKEN;
const API_VER   = "v19.0";

// Optional: set a shared secret in Acuity → Webhooks to verify requests
const ACUITY_SECRET = process.env.ACUITY_WEBHOOK_SECRET;

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Verify Acuity's HMAC-SHA256 signature (optional but recommended).
 * In Acuity: Settings → Integrations → Webhooks → set a secret.
 * Acuity sends the signature in the X-Acuity-Signature header.
 */
function verifySignature(req, rawBody) {
  if (!ACUITY_SECRET) return true; // skip if no secret configured
  const sig = req.headers["x-acuity-signature"];
  if (!sig) return false;
  const expected = crypto
    .createHmac("sha256", ACUITY_SECRET)
    .update(rawBody)
    .digest("hex");
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
}

/**
 * Generate a stable event_id from the Acuity appointment ID.
 * Pass this SAME value to your browser pixel: fbq('track', 'Lead', {}, { eventID: '<id>' })
 */
function buildEventId(appointmentId) {
  return `acuity_lead_${appointmentId}`;
}

// ── Handler ───────────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  // Collect raw body for signature verification
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const rawBody = Buffer.concat(chunks).toString();

  if (!verifySignature(req, rawBody)) {
    console.error("Invalid Acuity signature");
    return res.status(401).json({ error: "Unauthorized" });
  }

  let appointment;
  try {
    appointment = JSON.parse(rawBody);
  } catch (e) {
    return res.status(400).json({ error: "Invalid JSON" });
  }

  // ── Extract fields from Acuity payload ──────────────────────────────────────
  // Acuity webhook shape: https://developers.acuityscheduling.com/docs/webhooks
  const {
    id,           // appointment ID (unique)
    email,
    firstName,
    lastName,
    phone,
    ip,           // not always present, but use if available
  } = appointment;

  if (!id) {
    return res.status(400).json({ error: "Missing appointment id" });
  }

  // ── Build Meta CAPI payload ──────────────────────────────────────────────────
  const eventId   = buildEventId(id);
  const eventTime = Math.floor(Date.now() / 1000);

  const userData = {
    em: hash(email),
    ph: hash(phone),
    fn: hash(firstName),
    ln: hash(lastName),
    // If you can capture ip + user_agent from your site, pass them via
    // a query param on the webhook URL or store them separately.
    // client_ip_address and client_user_agent improve match quality.
  };

  // Strip undefined keys (Meta rejects nulls)
  Object.keys(userData).forEach(k => userData[k] === undefined && delete userData[k]);

  const body = {
    data: [
      {
        event_name:        "Lead",
        event_time:        eventTime,
        event_id:          eventId,
        event_source_url:  "https://yourdomain.com/book", // ← change to your booking page
        action_source:     "website",
        user_data:         userData,
        custom_data: {
          // Add anything useful: appointment type, service, value, etc.
          content_name: appointment.type || "Appointment",
        },
      },
    ],
    // Uncomment to use Meta's Test Events tool (get test_event_code from Events Manager)
    // test_event_code: "TEST12345",
  };

  // ── Send to Meta ─────────────────────────────────────────────────────────────
  const url = `https://graph.facebook.com/${API_VER}/${PIXEL_ID}/events?access_token=${API_TOKEN}`;

  let metaRes;
  try {
    metaRes = await fetch(url, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(body),
    });
  } catch (err) {
    console.error("Meta CAPI network error:", err);
    return res.status(502).json({ error: "Failed to reach Meta" });
  }

  const metaJson = await metaRes.json();

  if (!metaRes.ok) {
    console.error("Meta CAPI error:", JSON.stringify(metaJson));
    return res.status(502).json({ error: "Meta rejected the event", detail: metaJson });
  }

  console.log(`CAPI Lead sent — appointment ${id}, event_id: ${eventId}`, metaJson);
  return res.status(200).json({ success: true, event_id: eventId, meta: metaJson });
};
