/**
 * SHA-256 helper (WebCrypto) used for fingerprints and delete-token
 * hashing (ТЗ §4.2.1, §5.4, §6.1). Works in Workers, Node ≥ 22 and
 * browsers — `crypto.subtle` is available everywhere in the target
 * runtimes.
 */

/** sha256(bytes) → 32 bytes. */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', data as unknown as ArrayBuffer);
  return new Uint8Array(digest);
}

/** sha256 → lowercase hex (Redis `delete:{id}` value format, §6.1). */
export async function sha256Hex(data: Uint8Array): Promise<string> {
  const h = await sha256(data);
  let out = '';
  for (const b of h) out += b.toString(16).padStart(2, '0');
  return out;
}
