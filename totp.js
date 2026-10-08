export const ISSUER = "totp.jasiek.me";
export const PERIOD = 30;
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32(bytes) {
  let bits = 0;
  let value = 0;
  let result = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) result += ALPHABET[(value << (5 - bits)) & 31];
  return result;
}

export function validateLabel(value) {
  const label = value.trim();
  if (!label || label.length > 64 || /[:\p{Cc}]/u.test(label)) {
    throw new Error(
      "Use 1–64 characters, without colons or control characters.",
    );
  }
  return label;
}

export function createSecret() {
  return crypto.getRandomValues(new Uint8Array(20));
}

export function validateDigits(digits) {
  if (digits !== 6 && digits !== 8) throw new Error("Choose 6 or 8 digits.");
  return digits;
}

export function enrollmentUri(secret, value, digits = 6) {
  const label = validateLabel(value);
  const params = new URLSearchParams({
    secret: base32(secret),
    issuer: ISSUER,
    algorithm: "SHA1",
    digits: String(validateDigits(digits)),
    period: String(PERIOD),
  });
  return `otpauth://totp/${ISSUER}:${encodeURIComponent(label)}?${params}`;
}

export function importKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    secret,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
}

export async function codeAtCounter(key, counter, digits = 6) {
  validateDigits(digits);
  if (!Number.isSafeInteger(counter) || counter < 0)
    throw new Error("Invalid counter.");
  const buffer = new ArrayBuffer(8);
  new DataView(buffer).setBigUint64(0, BigInt(counter));
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, buffer));
  const offset = digest[digest.length - 1] & 15;
  const binary = new DataView(digest.buffer).getUint32(offset) & 0x7fffffff;
  return String(binary % 10 ** digits).padStart(digits, "0");
}

// Keep every matching step in the rare case of adjacent code collisions.
export async function matchingCounters(
  key,
  code,
  now = Date.now(),
  digits = 6,
) {
  validateDigits(digits);
  if (!new RegExp(`^\\d{${digits}}$`).test(code)) return [];
  const current = Math.floor(now / 1000 / PERIOD);
  const matches = [];
  for (const counter of [current, current - 1, current + 1]) {
    if (counter >= 0 && (await codeAtCounter(key, counter, digits)) === code)
      matches.push(counter);
  }
  return matches;
}

export async function verifyNextCode(
  key,
  code,
  firstCounters,
  now = Date.now(),
  digits = 6,
) {
  const matches = await matchingCounters(key, code, now, digits);
  return matches.some((counter) => firstCounters.includes(counter - 1));
}
