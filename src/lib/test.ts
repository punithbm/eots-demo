import { generateEOTSKeyPair, signEOTS, verifyEOTS, extractPrivateKey, deriveTaprootAddress, bytesToHex, generateRandomMessageHash, generateRandomNonce } from "./index";

// Test function to verify EOTS implementation
export function runEOTSTests(): void {
  console.log("🚀 Running EOTS Tests...\n");

  try {
    // Test 1: Key Generation
    console.log("1️⃣ Testing Key Generation");
    const keyPair = generateEOTSKeyPair();
    console.log("✅ Key pair generated successfully");
    console.log(`Private Key: ${bytesToHex(keyPair.privateKey)}`);
    console.log(`Public Key: ${bytesToHex(keyPair.publicKey)}`);

    // Test Taproot address derivation
    const taprootAddress = deriveTaprootAddress(keyPair.privateKey);
    console.log(`Taproot Address: ${taprootAddress}\n`);

    // Test 2: Signature Generation and Verification
    console.log("2️⃣ Testing Signature Generation and Verification");
    const messageHash = generateRandomMessageHash();
    console.log(`Message Hash: ${messageHash}`);

    const signature = signEOTS(keyPair.privateKey, messageHash);
    console.log("✅ Signature generated successfully");
    console.log(`Signature R: ${bytesToHex(signature.r)}`);
    console.log(`Signature S: ${bytesToHex(signature.s)}`);

    const isValid = verifyEOTS(keyPair.publicKey, messageHash, signature);
    console.log(`✅ Signature verification: ${isValid ? "VALID" : "INVALID"}\n`);

    // Test 3: Nonce Reuse and Private Key Extraction
    console.log("3️⃣ Testing Private Key Extraction (Nonce Reuse)");
    const nonce = generateRandomNonce();
    const messageHash1 = generateRandomMessageHash();
    const messageHash2 = generateRandomMessageHash();

    console.log(`Using same nonce for two different messages:`);
    console.log(`Nonce: ${nonce}`);
    console.log(`Message Hash 1: ${messageHash1}`);
    console.log(`Message Hash 2: ${messageHash2}`);

    const sig1 = signEOTS(keyPair.privateKey, messageHash1, nonce);
    const sig2 = signEOTS(keyPair.privateKey, messageHash2, nonce);

    console.log("✅ Two signatures generated with same nonce");

    // Extract private key
    const extractedKey = extractPrivateKey(sig1, sig2, messageHash1, messageHash2);
    const extractedKeyHex = bytesToHex(extractedKey);
    const originalKeyHex = bytesToHex(keyPair.privateKey);

    console.log(`Original Private Key:  ${originalKeyHex}`);
    console.log(`Extracted Private Key: ${extractedKeyHex}`);
    console.log(`✅ Keys match: ${originalKeyHex === extractedKeyHex ? "YES" : "NO"}\n`);

    // Test 4: Error Cases
    console.log("4️⃣ Testing Error Cases");

    try {
      // Try to extract private key from signatures with different nonces
      const differentNonce = generateRandomNonce();
      const sig3 = signEOTS(keyPair.privateKey, messageHash1, nonce);
      const sig4 = signEOTS(keyPair.privateKey, messageHash2, differentNonce);

      extractPrivateKey(sig3, sig4, messageHash1, messageHash2);
      console.log("❌ Should have failed - different nonces used");
    } catch {
      console.log("✅ Correctly detected different nonces");
    }

    console.log("\n🎉 All tests completed successfully!");
  } catch (error) {
    console.error("❌ Test failed:", error);
    throw error;
  }
}

// Auto-run tests if this module is imported
if (typeof window !== "undefined") {
  // Browser environment - add to window for manual testing
  (window as unknown as Record<string, unknown>).runEOTSTests = runEOTSTests;
} else {
  // Node environment - run immediately if executed directly
  if (require.main === module) {
    runEOTSTests();
  }
}
