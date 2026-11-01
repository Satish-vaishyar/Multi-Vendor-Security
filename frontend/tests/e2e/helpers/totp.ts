import { createHmac } from 'crypto';

/** RFC 4648 base32 decode (no padding required). */
function base32Decode(input: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = input.replace(/=+$/, '').replace(/\s+/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx < 0) throw new Error(`invalid base32 character: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/**
 * RFC 6238 TOTP (HMAC-SHA1, 30 s step, 6 digits) - the defaults every authenticator app uses.
 * `offsetSteps` shifts the time window (e.g. +1 gives the next code, used to get a fresh code after a replay guard).
 */
export function totp(secretBase32: string, offsetSteps = 0, nowMs = Date.now(), digits = 6, stepS = 30): string {
  const counter = Math.floor(nowMs / 1000 / stepS) + offsetSteps;
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac('sha1', base32Decode(secretBase32)).update(buf).digest();
  const off = mac[mac.length - 1] & 0x0f;
  const bin =
    ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}

/** Self-check against the RFC 6238 appendix B vector (secret "12345678901234567890", T=59 -> 94287082, 8 digits). */
export function totpSelfTest(): boolean {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  return totp(secret, 0, 59_000, 8) === '94287082';
}

/**
 * A code the server will accept that is newer than `lastStep` (the server rejects a time-step it already saw).
 * Valid window is +/-1 step, so after one use in the current step the next one is the following step.
 */
export function totpAfter(secretBase32: string, lastStep = 0, nowMs = Date.now()): { code: string; step: number } {
  const cur = Math.floor(nowMs / 1000 / 30);
  for (const off of [0, 1, -1]) {
    if (cur + off > lastStep) return { code: totp(secretBase32, off, nowMs), step: cur + off };
  }
  throw new Error('no unused TOTP step available; wait 30 seconds');
}
