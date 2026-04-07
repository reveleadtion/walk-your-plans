const crypto = require("crypto");

function hash(value) {
  if (!value) return undefined;
  return crypto
    .createHash("sha256")
    .update(value.trim().toLowerCase())
    .digest("hex");
}

module.exports = { hash };
