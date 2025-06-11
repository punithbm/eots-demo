import { generateEOTSKeyPair, signEOTS, verifyEOTS, extractPrivateKey, deriveTaprootAddress, bytesToHex, generateRandomMessageHash, generateRandomNonce } from "./index";

/**
 * Demo: Show how EOTS signatures reveal private keys when nonces are reused
 */
export function demonstrateNonceReuse(): {
  originalPrivateKey: string;
  extractedPrivateKey: string;
  match: boolean;
  taprootAddress: string;
  signatures: {
    sig1: { r: string; s: string; message: string };
    sig2: { r: string; s: string; message: string };
  };
} {
  console.log("🔍 EOTS Nonce Reuse Demonstration\n");

  // Step 1: Generate a key pair
  const keyPair = generateEOTSKeyPair();
  const privateKeyHex = bytesToHex(keyPair.privateKey);
  console.log("1. Generated Key Pair");
  console.log(`   Private Key: ${privateKeyHex}`);
  console.log(`   Public Key: ${bytesToHex(keyPair.publicKey)}\n`);

  // Step 2: Generate the same nonce (this is the vulnerability!)
  const sharedNonce = generateRandomNonce();
  console.log("2. Using the same nonce for two different messages (BAD!)");
  console.log(`   Shared Nonce: ${sharedNonce}\n`);

  // Step 3: Create two different messages
  const messageHash1 = generateRandomMessageHash();
  const messageHash2 = generateRandomMessageHash();
  console.log("3. Two different messages:");
  console.log(`   Message 1 Hash: ${messageHash1}`);
  console.log(`   Message 2 Hash: ${messageHash2}\n`);

  // Step 4: Sign both messages with the same nonce
  const sig1 = signEOTS(keyPair.privateKey, messageHash1, sharedNonce);
  const sig2 = signEOTS(keyPair.privateKey, messageHash2, sharedNonce);

  console.log("4. Generated signatures:");
  console.log(`   Signature 1: r=${bytesToHex(sig1.r)}, s=${bytesToHex(sig1.s)}`);
  console.log(`   Signature 2: r=${bytesToHex(sig2.r)}, s=${bytesToHex(sig2.s)}\n`);

  // Step 5: Verify both signatures are valid
  const valid1 = verifyEOTS(keyPair.publicKey, messageHash1, sig1);
  const valid2 = verifyEOTS(keyPair.publicKey, messageHash2, sig2);

  console.log("5. Signature verification:");
  console.log(`   Signature 1 valid: ${valid1}`);
  console.log(`   Signature 2 valid: ${valid2}\n`);

  // Step 6: Extract the private key (the attack!)
  console.log("6. 🚨 Extracting private key from nonce reuse...");
  const extractedKey = extractPrivateKey(sig1, sig2, messageHash1, messageHash2);
  const extractedKeyHex = bytesToHex(extractedKey);

  console.log(`   Original Private Key:  ${privateKeyHex}`);
  console.log(`   Extracted Private Key: ${extractedKeyHex}`);

  const keysMatch = privateKeyHex.toLowerCase() === extractedKeyHex.toLowerCase();
  console.log(`   Keys Match: ${keysMatch ? "✅ YES" : "❌ NO"}\n`);

  // Step 7: Show Bitcoin address
  const taprootAddress = deriveTaprootAddress(keyPair.privateKey);
  console.log("7. Bitcoin Taproot Address:");
  console.log(`   ${taprootAddress}\n`);

  console.log("💡 This demonstrates why nonce reuse is catastrophic in EOTS!\n");

  return {
    originalPrivateKey: privateKeyHex,
    extractedPrivateKey: extractedKeyHex,
    match: keysMatch,
    taprootAddress,
    signatures: {
      sig1: {
        r: bytesToHex(sig1.r),
        s: bytesToHex(sig1.s),
        message: messageHash1,
      },
      sig2: {
        r: bytesToHex(sig2.r),
        s: bytesToHex(sig2.s),
        message: messageHash2,
      },
    },
  };
}

/**
 * Demo: Show proper EOTS usage with unique nonces
 */
export function demonstrateProperUsage(): void {
  console.log("✅ EOTS Proper Usage Demonstration\n");

  // Generate key pair
  const keyPair = generateEOTSKeyPair();
  console.log("1. Generated Key Pair");
  console.log(`   Private Key: ${bytesToHex(keyPair.privateKey)}`);
  console.log(`   Public Key: ${bytesToHex(keyPair.publicKey)}\n`);

  // Sign multiple messages with different nonces
  const messages = [generateRandomMessageHash(), generateRandomMessageHash(), generateRandomMessageHash()];

  console.log("2. Signing multiple messages with unique nonces:");

  const signatures = messages.map((messageHash, index) => {
    const signature = signEOTS(keyPair.privateKey, messageHash); // No nonce = unique deterministic nonce
    const isValid = verifyEOTS(keyPair.publicKey, messageHash, signature);

    console.log(`   Message ${index + 1}:`);
    console.log(`     Hash: ${messageHash}`);
    console.log(`     Signature R: ${bytesToHex(signature.r)}`);
    console.log(`     Signature S: ${bytesToHex(signature.s)}`);
    console.log(`     Valid: ${isValid}\n`);

    return { messageHash, signature, isValid };
  });

  // Try to extract private key (should fail)
  console.log("3. Attempting to extract private key from different nonces:");
  try {
    extractPrivateKey(signatures[0].signature, signatures[1].signature, signatures[0].messageHash, signatures[1].messageHash);
    console.log("   ❌ UNEXPECTED: Private key extracted (this should not happen!)");
  } catch (error) {
    console.log("   ✅ SUCCESS: Cannot extract private key with different nonces");
    console.log(`   Error: ${error}\n`);
  }

  console.log("💡 This shows proper EOTS usage with unique nonces is secure!\n");
}

// Make functions available globally for browser console
if (typeof window !== "undefined") {
  (window as unknown as Record<string, unknown>).demonstrateNonceReuse = demonstrateNonceReuse;
  (window as unknown as Record<string, unknown>).demonstrateProperUsage = demonstrateProperUsage;
}
