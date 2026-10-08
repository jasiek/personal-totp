import { test } from "node:test";
import assert from "node:assert/strict";
import {
  base32,
  createSecret,
  enrollmentUri,
  importKey,
  codeAtCounter,
  matchingCounters,
  validateLabel,
  verifyNextCode,
} from "../totp.js";

const rfcSecret = new TextEncoder().encode("12345678901234567890");

test("Base32 matches RFC 4648 vectors without padding", () => {
  for (const [raw, encoded] of [
    ["", ""],
    ["f", "MY"],
    ["fo", "MZXQ"],
    ["foo", "MZXW6"],
    ["foob", "MZXW6YQ"],
    ["fooba", "MZXW6YTB"],
    ["foobar", "MZXW6YTBOI"],
  ]) {
    assert.equal(base32(new TextEncoder().encode(raw)), encoded);
  }
});

test("Web Crypto produces a 160-bit secret", () => {
  const secret = createSecret();
  assert.equal(secret.byteLength, 20);
  assert.match(base32(secret), /^[A-Z2-7]{32}$/);
  assert.notDeepEqual(createSecret(), secret);
});

test("SHA-1 TOTP matches every RFC 6238 vector, including large timestamps", async () => {
  const key = await importKey(rfcSecret);
  assert.equal(key.extractable, false);
  for (const [seconds, expected] of [
    [59, "94287082"],
    [1111111109, "07081804"],
    [1111111111, "14050471"],
    [1234567890, "89005924"],
    [2000000000, "69279037"],
    [20000000000, "65353130"],
  ]) {
    assert.equal(
      await codeAtCounter(key, Math.floor(seconds / 30), 8),
      expected,
    );
    assert.equal(
      await codeAtCounter(key, Math.floor(seconds / 30)),
      expected.slice(-6),
    );
  }
});

test("six-digit HOTP vectors preserve leading zeroes", async () => {
  const key = await importKey(rfcSecret);
  const expected = [
    "755224",
    "287082",
    "359152",
    "969429",
    "338314",
    "254676",
    "287922",
    "162583",
    "399871",
    "520489",
  ];
  for (let i = 0; i < expected.length; i++)
    assert.equal(await codeAtCounter(key, i), expected[i]);
});

test("enrollment URI preserves issuer and safely encodes user labels", () => {
  const uri = new URL(enrollmentUri(rfcSecret, "  Żółć & family / ? # 🏡  "));
  assert.equal(uri.protocol, "otpauth:");
  assert.equal(uri.host, "totp");
  assert.equal(
    decodeURIComponent(uri.pathname),
    "/totp.jasiek.me:Żółć & family / ? # 🏡",
  );
  assert.equal(uri.searchParams.get("issuer"), "totp.jasiek.me");
  assert.equal(
    uri.searchParams.get("secret"),
    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
  );
  assert.equal(uri.searchParams.get("algorithm"), "SHA1");
  assert.equal(uri.searchParams.get("digits"), "6");
  assert.equal(uri.searchParams.get("period"), "30");
  assert.equal(uri.hash, "");
  for (const invalid of ["", "   ", "family:one", "a".repeat(65), "a\nb"])
    assert.throws(() => validateLabel(invalid));
});

test("enrollment uses the selected length and rejects unsupported lengths", async () => {
  const key = await importKey(rfcSecret);
  for (const digits of [6, 8]) {
    const uri = new URL(enrollmentUri(rfcSecret, "Family", digits));
    assert.equal(uri.searchParams.get("digits"), String(digits));
  }
  for (const digits of [0, 7, 9, "8", NaN]) {
    assert.throws(() => enrollmentUri(rfcSecret, "Family", digits));
    await assert.rejects(codeAtCounter(key, 1, digits));
    await assert.rejects(matchingCounters(key, "12345678", 59000, digits));
  }
});

test("eight-digit verification preserves leading zeroes and rejects six-digit codes", async () => {
  const key = await importKey(rfcSecret);
  const now = 1111111109000;
  const current = Math.floor(now / 30000);
  const first = await matchingCounters(key, "07081804", now, 8);
  assert.deepEqual(first, [current]);
  assert.deepEqual(await matchingCounters(key, "081804", now, 8), []);
  assert.deepEqual(await matchingCounters(key, "07081804", now, 6), []);
  assert.equal(await verifyNextCode(key, "07081804", first, now, 8), false);
  assert.equal(
    await verifyNextCode(key, "14050471", first, now + 30000, 8),
    true,
  );
  assert.equal(
    await verifyNextCode(key, "050471", first, now + 30000, 8),
    false,
  );
  assert.equal(
    await verifyNextCode(key, "14050471", first, now + 120000, 8),
    false,
  );
  const skipped = await codeAtCounter(key, current + 2, 8);
  assert.equal(
    await verifyNextCode(key, skipped, first, now + 60000, 8),
    false,
  );
  for (const delta of [-1, 0, 1]) {
    const code = await codeAtCounter(key, current + delta, 8);
    assert.ok(
      (await matchingCounters(key, code, now, 8)).includes(current + delta),
    );
  }
  for (const delta of [-2, 2]) {
    const code = await codeAtCounter(key, current + delta, 8);
    assert.deepEqual(await matchingCounters(key, code, now, 8), []);
  }
});

test("verification accepts only current or adjacent time steps", async () => {
  const key = await importKey(rfcSecret);
  const now = 1234567890000;
  const current = Math.floor(now / 30000);
  for (const delta of [-1, 0, 1]) {
    assert.ok(
      (
        await matchingCounters(
          key,
          await codeAtCounter(key, current + delta),
          now,
        )
      ).includes(current + delta),
    );
  }
  for (const delta of [-2, 2])
    assert.deepEqual(
      await matchingCounters(
        key,
        await codeAtCounter(key, current + delta),
        now,
      ),
      [],
    );
  for (const bad of ["12345", "1234567", "abcdef", " 123456", "<svg/>"])
    assert.deepEqual(await matchingCounters(key, bad, now), []);
});

test("confirmation requires consecutive codes and rejects replay, skipped and expired codes", async () => {
  const key = await importKey(rfcSecret);
  const now = 1234567890000;
  const current = Math.floor(now / 30000);
  const first = await matchingCounters(
    key,
    await codeAtCounter(key, current),
    now,
  );
  assert.equal(
    await verifyNextCode(key, await codeAtCounter(key, current), first, now),
    false,
  );
  assert.equal(
    await verifyNextCode(
      key,
      await codeAtCounter(key, current + 1),
      first,
      now + 30000,
    ),
    true,
  );
  assert.equal(
    await verifyNextCode(
      key,
      await codeAtCounter(key, current + 2),
      first,
      now + 60000,
    ),
    false,
  );
  assert.equal(
    await verifyNextCode(
      key,
      await codeAtCounter(key, current + 1),
      first,
      now + 120000,
    ),
    false,
  );
  assert.equal(
    await verifyNextCode(key, await codeAtCounter(key, current + 1), [], now),
    false,
  );
});
