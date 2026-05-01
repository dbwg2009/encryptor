// Crypto module — runs entirely in the browser.
//
// Three independent uses:
//   1. ASCII cipher (encryptText/decryptToken)  — for the encrypt/decrypt tool;
//      byte-for-byte compatible with the original Python implementation.
//   2. KDF (deriveAuthAndVault) — turns the master password into {authHash, vaultKey}.
//   3. AES-GCM (sealVault/openVault) — for storing vault entries server-side.

const subtle = crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: false });

// ─── helpers ────────────────────────────────────────────────────
export function bytesToHex(b) {
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
  return s;
}
export function hexToBytes(hex) {
  if (hex.length % 2) throw new Error("bad hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const v = parseInt(hex.substr(i * 2, 2), 16);
    if (Number.isNaN(v)) throw new Error("bad hex");
    out[i] = v;
  }
  return out;
}
export function bytesToB64(b) {
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s);
}
export function b64ToBytes(b64) {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
function ctEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a[i] ^ b[i];
  return r === 0;
}

// ─── ASCII cipher (interoperable with Python) ──────────────────
// Format: hex(salt) ":" hex(ct) ":" hex(tag)
// PBKDF2-HMAC-SHA256, 200k rounds, 64 bytes derived (split 32/32).
// Keystream: SHA256(enc_key || salt || counter_be32) blocks. CT = PT XOR KS.
// Tag: HMAC-SHA256(mac_key, salt || ct).
const CIPHER_SALT_LEN = 16;
const CIPHER_ITERATIONS = 200_000;
const CIPHER_KEY_LEN = 32;

async function deriveCipherKeys(password, salt) {
  const baseKey = await subtle.importKey(
    "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]
  );
  const bits = await subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: CIPHER_ITERATIONS, hash: "SHA-256" },
    baseKey,
    CIPHER_KEY_LEN * 2 * 8
  );
  const km = new Uint8Array(bits);
  return [km.slice(0, CIPHER_KEY_LEN), km.slice(CIPHER_KEY_LEN)];
}

async function keystream(encKey, salt, length) {
  const out = new Uint8Array(length);
  const buf = new Uint8Array(encKey.length + salt.length + 4);
  buf.set(encKey, 0);
  buf.set(salt, encKey.length);
  const counterView = new DataView(buf.buffer, encKey.length + salt.length, 4);
  let counter = 0, off = 0;
  while (off < length) {
    counterView.setUint32(0, counter, false);
    const digest = new Uint8Array(await subtle.digest("SHA-256", buf));
    const take = Math.min(digest.length, length - off);
    out.set(digest.subarray(0, take), off);
    off += take;
    counter += 1;
  }
  return out;
}

async function hmacSha256(key, data) {
  const k = await subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle.sign("HMAC", k, data));
}

export async function encryptText(plaintext, password) {
  const data = enc.encode(plaintext);
  const salt = crypto.getRandomValues(new Uint8Array(CIPHER_SALT_LEN));
  const [encKey, macKey] = await deriveCipherKeys(password, salt);
  const ks = await keystream(encKey, salt, data.length);
  const ct = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) ct[i] = data[i] ^ ks[i];
  const macInput = new Uint8Array(salt.length + ct.length);
  macInput.set(salt, 0);
  macInput.set(ct, salt.length);
  const tag = await hmacSha256(macKey, macInput);
  return `${bytesToHex(salt)}:${bytesToHex(ct)}:${bytesToHex(tag)}`;
}

export async function decryptToken(token, password) {
  const parts = token.trim().split(":");
  if (parts.length !== 3) return { ok: false, err: "invalid format" };
  let salt, ct, tag;
  try {
    salt = hexToBytes(parts[0]);
    ct   = hexToBytes(parts[1]);
    tag  = hexToBytes(parts[2]);
  } catch { return { ok: false, err: "decryption failed" }; }
  if (salt.length !== CIPHER_SALT_LEN) return { ok: false, err: "invalid format" };
  const [encKey, macKey] = await deriveCipherKeys(password, salt);
  const macInput = new Uint8Array(salt.length + ct.length);
  macInput.set(salt, 0);
  macInput.set(ct, salt.length);
  const expected = await hmacSha256(macKey, macInput);
  if (!ctEqual(tag, expected)) return { ok: false, err: "wrong key or tampered" };
  const ks = await keystream(encKey, salt, ct.length);
  const pt = new Uint8Array(ct.length);
  for (let i = 0; i < ct.length; i++) pt[i] = ct[i] ^ ks[i];
  return { ok: true, text: dec.decode(pt) };
}

// ─── Auth + vault KDF ──────────────────────────────────────────
// Single PBKDF2 call produces 64 random bytes; first 32 = authHash sent to
// server, last 32 = vaultKey kept in memory. Server only ever sees authHash
// (and re-hashes it with Argon2id before storage).
export async function deriveAuthAndVault(password, saltHex, iterations = 200_000) {
  const salt = hexToBytes(saltHex);
  const baseKey = await subtle.importKey(
    "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]
  );
  const bits = await subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    baseKey,
    64 * 8
  );
  const km = new Uint8Array(bits);
  return {
    authHash: bytesToHex(km.slice(0, 32)),
    vaultKey: km.slice(32),
  };
}

// ─── Group key derivation ──────────────────────────────────────
// Same shape as deriveAuthAndVault but with a group's passcode + salt.
// authHash is sent to the server as a verifier; groupKey is used client-side
// (1) as the AES-GCM key to encrypt/decrypt group messages, and (2) it can be
// wrapped under the user's vaultKey for storage.
export async function deriveGroupAuth(passcode, saltHex, iterations = 200_000) {
  return deriveAuthAndVault(passcode, saltHex, iterations);
}

// ─── AES-GCM for vault items ───────────────────────────────────
// Wire format: base64( iv(12) || ciphertext+tag ).
async function importAesKey(rawKey) {
  return await subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function sealString(plaintext, vaultKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await importAesKey(vaultKey);
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plaintext)));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return bytesToB64(out);
}

export async function openString(b64, vaultKey) {
  const buf = b64ToBytes(b64);
  if (buf.length < 13) throw new Error("ciphertext too short");
  const iv = buf.subarray(0, 12);
  const ct = buf.subarray(12);
  const key = await importAesKey(vaultKey);
  const pt = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv }, key, ct));
  return dec.decode(pt);
}

export async function sealJson(obj, vaultKey) { return sealString(JSON.stringify(obj), vaultKey); }
export async function openJson(b64, vaultKey) { return JSON.parse(await openString(b64, vaultKey)); }

// Wrap an arbitrary byte array (e.g. a 32-byte group key) under another key.
export async function sealBytes(bytes, wrappingKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await importAesKey(wrappingKey);
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, key, bytes));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return bytesToB64(out);
}
export async function openBytes(b64, wrappingKey) {
  const buf = b64ToBytes(b64);
  if (buf.length < 13) throw new Error("ciphertext too short");
  const iv = buf.subarray(0, 12);
  const ct = buf.subarray(12);
  const key = await importAesKey(wrappingKey);
  return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv }, key, ct));
}

// ─── Media encryption ──────────────────────────────────────────
// Encrypt a file with a freshly-generated random 32-byte key.
// Returns { ciphertext, fileKeyHex } — caller embeds fileKeyHex in the
// (otherwise encrypted) message body so the recipient can decrypt.
export async function encryptFile(bytes) {
  const fileKey = crypto.getRandomValues(new Uint8Array(32));
  const ciphertext = await sealBytes(bytes, fileKey);
  // sealBytes returns base64 — convert back to bytes for upload
  return { ciphertext: b64ToBytes(ciphertext), fileKeyHex: bytesToHex(fileKey) };
}

export async function decryptFile(bytes, fileKeyHex) {
  const fileKey = hexToBytes(fileKeyHex);
  return openBytes(bytesToB64(bytes), fileKey);
}

// ─── Passphrase generator ──────────────────────────────────────
export function generatePassphrase(length = 24) {
  const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*";
  const buf = crypto.getRandomValues(new Uint32Array(length));
  let s = "";
  for (let i = 0; i < length; i++) s += alphabet[buf[i] % alphabet.length];
  return s;
}

// ─── Strength meter (matches Python entropy estimator) ─────────
export function passwordStrength(pw) {
  if (!pw) return { bits: 0, label: "—", klass: "", pct: 0 };
  const hLo = /[a-z]/.test(pw);
  const hUp = /[A-Z]/.test(pw);
  const hDi = /[0-9]/.test(pw);
  const hSy = /[^A-Za-z0-9]/.test(pw);
  const pool = Math.max((hLo ? 26 : 0) + (hUp ? 26 : 0) + (hDi ? 10 : 0) + (hSy ? 32 : 0), 26);
  const bits = pw.length * Math.log2(pool);
  let label, klass, pct;
  if      (bits < 40)  { label = "Weak";   klass = "s-weak";   pct = Math.min(bits / 40 * 33, 33); }
  else if (bits < 72)  { label = "Fair";   klass = "s-fair";   pct = 33 + (bits - 40) / 32 * 27; }
  else if (bits < 100) { label = "Good";   klass = "s-good";   pct = 60 + (bits - 72) / 28 * 25; }
  else                 { label = "Strong"; klass = "s-strong"; pct = Math.min(85 + (bits - 100) / 50 * 15, 100); }
  return { bits, label, klass, pct };
}
