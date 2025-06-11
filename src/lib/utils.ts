/**
 * Convert hex string to Uint8Array
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.startsWith("0x")) {
    hex = hex.slice(2);
  }
  if (hex.length % 2 !== 0) {
    hex = "0" + hex;
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Generate random 32-byte value as hex string
 */
export function generateRandomHex32(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

/**
 * Generate random private key (32 bytes)
 */
export function generateRandomPrivateKey(): string {
  return generateRandomHex32();
}

/**
 * Generate random nonce (32 bytes)
 */
export function generateRandomNonce(): string {
  return generateRandomHex32();
}

/**
 * Generate random message hash (32 bytes)
 */
export function generateRandomMessageHash(): string {
  return generateRandomHex32();
}

/**
 * Validate hex string
 */
export function isValidHex(hex: string, expectedLength?: number): boolean {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  const hexRegex = /^[0-9a-fA-F]*$/;
  const isValid = hexRegex.test(cleanHex);

  if (expectedLength) {
    return isValid && cleanHex.length === expectedLength * 2;
  }

  return isValid && cleanHex.length > 0 && cleanHex.length % 2 === 0;
}
