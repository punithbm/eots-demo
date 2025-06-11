export interface EOTSKeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export interface EOTSSignature {
  r: Uint8Array;
  s: Uint8Array;
}

export interface SignatureInput {
  privateKey: string;
  messageHash: string;
  nonce: string;
}

export interface VerificationInput {
  publicKey: string;
  messageHash: string;
  signature: {
    r: string;
    s: string;
  };
}

export interface ExtractionInput {
  signature1: {
    r: string;
    s: string;
  };
  signature2: {
    r: string;
    s: string;
  };
  messageHash1: string;
  messageHash2: string;
}
