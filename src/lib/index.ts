export * from "./types";
export * from "./utils";
export * from "./eots";

// Re-export main functions for convenience
export { generateEOTSKeyPair, signEOTS, verifyEOTS, extractPrivateKey, deriveTaprootAddress, getPublicKey, signatureToFullHex } from "./eots";

export { hexToBytes, bytesToHex, generateRandomPrivateKey, generateRandomNonce, generateRandomMessageHash, isValidHex } from "./utils";
