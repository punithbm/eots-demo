"use client";

import { useState } from "react";
import { generateEOTSKeyPair, signEOTS, verifyEOTS, extractPrivateKey, deriveTaprootAddress, getPublicKey, signatureToFullHex, bytesToHex, hexToBytes, generateRandomPrivateKey, generateRandomNonce, generateRandomMessageHash, isValidHex } from "@/lib";
import { sha256 } from "@noble/hashes/sha256";
import type { EOTSSignature } from "@/lib";
// import { runEOTSTests } from "@/lib/test";

interface FormData {
  privateKey: string;
  nonce: string;
  messageText: string;
  messageHash: string;
  publicKey: string;
  signatureR: string;
  signatureS: string;
  signature1R: string;
  signature1S: string;
  signature2R: string;
  signature2S: string;
  messageHash1: string;
  messageHash2: string;
}

export default function Home() {
  const [formData, setFormData] = useState<FormData>({
    privateKey: "",
    nonce: "",
    messageText: "",
    messageHash: "",
    publicKey: "",
    signatureR: "",
    signatureS: "",
    signature1R: "",
    signature1S: "",
    signature2R: "",
    signature2S: "",
    messageHash1: "",
    messageHash2: "",
  });

  const [results, setResults] = useState({
    generatedSignature: null as EOTSSignature | null,
    verificationResult: null as boolean | null,
    extractedPrivateKey: "",
    taprootAddress: "",
    generatedPublicKey: "",
  });

  const [errors, setErrors] = useState<string[]>([]);

  const updateFormData = (field: keyof FormData, value: string) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
  };

  const generateRandom = (field: keyof FormData) => {
    let value = "";
    switch (field) {
      case "privateKey":
        value = generateRandomPrivateKey();
        break;
      case "nonce":
        value = generateRandomNonce();
        break;
      case "messageHash":
      case "messageHash1":
      case "messageHash2":
        value = generateRandomMessageHash();
        break;
    }
    updateFormData(field, value);
  };

  const handleMessageTextChange = (text: string) => {
    updateFormData("messageText", text);
    if (text.trim()) {
      // Convert text to bytes and hash it
      const messageBytes = new TextEncoder().encode(text);
      const hashBytes = sha256(messageBytes);
      const hashHex = bytesToHex(hashBytes);
      updateFormData("messageHash", hashHex);
    } else {
      updateFormData("messageHash", "");
    }
  };

  const handleGenerateSignature = () => {
    try {
      setErrors([]);

      if (!formData.privateKey || !formData.messageHash) {
        setErrors(["Private key and message hash are required"]);
        return;
      }

      if (!isValidHex(formData.privateKey, 32)) {
        setErrors(["Invalid private key format (must be 64 hex characters)"]);
        return;
      }

      if (!isValidHex(formData.messageHash, 32)) {
        setErrors(["Invalid message hash format (must be 64 hex characters)"]);
        return;
      }

      if (formData.nonce && !isValidHex(formData.nonce, 32)) {
        setErrors(["Invalid nonce format (must be 64 hex characters)"]);
        return;
      }

      const signature = signEOTS(formData.privateKey, formData.messageHash, formData.nonce || undefined);

      const publicKey = getPublicKey(formData.privateKey);
      const taprootAddress = deriveTaprootAddress(formData.privateKey);

      setResults((prev) => ({
        ...prev,
        generatedSignature: signature,
        generatedPublicKey: bytesToHex(publicKey),
        taprootAddress,
      }));

      // Auto-fill verification form
      updateFormData("publicKey", bytesToHex(publicKey));
      updateFormData("signatureR", bytesToHex(signature.r));
      updateFormData("signatureS", bytesToHex(signature.s));
    } catch (error) {
      setErrors([`Error generating signature: ${error}`]);
    }
  };

  const handleVerifySignature = () => {
    try {
      setErrors([]);

      if (!formData.publicKey || !formData.messageHash || !formData.signatureR || !formData.signatureS) {
        setErrors(["Public key, message hash, and signature (r, s) are required"]);
        return;
      }

      if (!isValidHex(formData.publicKey, 33)) {
        setErrors(["Invalid public key format (must be 66 hex characters for compressed key)"]);
        return;
      }

      const signature: EOTSSignature = {
        r: hexToBytes(formData.signatureR),
        s: hexToBytes(formData.signatureS),
      };

      const isValid = verifyEOTS(formData.publicKey, formData.messageHash, signature);

      setResults((prev) => ({
        ...prev,
        verificationResult: isValid,
      }));
    } catch (error) {
      setErrors([`Error verifying signature: ${error}`]);
    }
  };

  const handleExtractPrivateKey = () => {
    try {
      setErrors([]);

      if (!formData.signature1R || !formData.signature1S || !formData.signature2R || !formData.signature2S || !formData.messageHash1 || !formData.messageHash2) {
        setErrors(["All signature components and message hashes are required"]);
        return;
      }

      const sig1: EOTSSignature = {
        r: hexToBytes(formData.signature1R),
        s: hexToBytes(formData.signature1S),
      };

      const sig2: EOTSSignature = {
        r: hexToBytes(formData.signature2R),
        s: hexToBytes(formData.signature2S),
      };

      const extractedKey = extractPrivateKey(sig1, sig2, formData.messageHash1, formData.messageHash2);
      const extractedKeyHex = bytesToHex(extractedKey);
      const taprootAddress = deriveTaprootAddress(extractedKey);

      setResults((prev) => ({
        ...prev,
        extractedPrivateKey: extractedKeyHex,
        taprootAddress,
      }));
    } catch (error) {
      setErrors([`Error extracting private key: ${error}`]);
    }
  };

  const handleGenerateKeyPair = () => {
    const keyPair = generateEOTSKeyPair();
    updateFormData("privateKey", bytesToHex(keyPair.privateKey));
    updateFormData("publicKey", bytesToHex(keyPair.publicKey));

    const taprootAddress = deriveTaprootAddress(keyPair.privateKey);
    setResults((prev) => ({
      ...prev,
      generatedPublicKey: bytesToHex(keyPair.publicKey),
      taprootAddress,
    }));
  };

  const handleRefresh = () => {
    setFormData({
      privateKey: "",
      nonce: "",
      messageText: "",
      messageHash: "",
      publicKey: "",
      signatureR: "",
      signatureS: "",
      signature1R: "",
      signature1S: "",
      signature2R: "",
      signature2S: "",
      messageHash1: "",
      messageHash2: "",
    });
    setResults({
      generatedSignature: null,
      verificationResult: null,
      extractedPrivateKey: "",
      taprootAddress: "",
      generatedPublicKey: "",
    });
    setErrors([]);
  };

  // const handleRunTests = () => {
  //   try {
  //     runEOTSTests();
  //     alert("✅ All tests passed! Check the browser console for detailed results.");
  //   } catch (error) {
  //     alert("❌ Tests failed! Check the browser console for details.");
  //     console.error("Test error:", error);
  //   }
  // };

  return (
    <div className="container mx-auto p-6 max-w-4xl">
      <h1 className="text-3xl font-bold text-center mb-8">Extractable One-Time Signatures (EOTS) Algorithm Demo</h1>

      {errors.length > 0 && (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-6">
          {errors.map((error, index) => (
            <p key={index}>{error}</p>
          ))}
        </div>
      )}

      {/* Key Generation Section */}
      <div className="bg-white shadow-lg rounded-lg p-6 mb-6">
        <h2 className="text-xl font-semibold mb-4">1. Key Generation</h2>
        <div className="mb-4">
          <button onClick={handleGenerateKeyPair} className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">
            Generate New Key Pair
          </button>
          <p className="text-sm text-gray-600 mt-2">This will generate a new private/public key pair and populate the private key field below for signing.</p>
        </div>

        {results.generatedPublicKey && (
          <div className="mt-4">
            <h3 className="font-semibold">Generated Public Key:</h3>
            <p className="text-sm font-mono bg-gray-100 p-2 rounded break-all">{results.generatedPublicKey}</p>
            {results.taprootAddress && (
              <>
                <h3 className="font-semibold mt-2">Taproot Address:</h3>
                <p className="text-sm font-mono bg-gray-100 p-2 rounded break-all">{results.taprootAddress}</p>
              </>
            )}
          </div>
        )}
      </div>

      {/* Signature Generation Section */}
      <div className="bg-white shadow-lg rounded-lg p-6 mb-6">
        <h2 className="text-xl font-semibold mb-4">2. Generate EOTS Signature</h2>

        <div className="grid grid-cols-1 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Private Key (32 bytes hex)</label>
            <div className="flex gap-2">
              <input type="text" value={formData.privateKey} onChange={(e) => updateFormData("privateKey", e.target.value)} className="flex-1 border border-gray-300 rounded-md px-3 py-2 text-sm font-mono" placeholder="Enter private key, generate key pair above, or generate random" />
              <button onClick={() => generateRandom("privateKey")} className="bg-gray-500 hover:bg-gray-700 text-white text-xs px-3 py-2 rounded">
                Generate Random
              </button>
            </div>
            {formData.privateKey && <p className="text-xs text-green-600 mt-1">✓ Private key populated. You can edit it or use it to generate signatures.</p>}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Message Text (will be SHA-256 hashed)</label>
            <textarea value={formData.messageText} onChange={(e) => handleMessageTextChange(e.target.value)} className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm" placeholder="Enter your message text here... (e.g., 'Hello World')" rows={3} />
            <p className="text-xs text-gray-500 mt-1">Or use the message hash field below for direct hash input</p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Message Hash (32 bytes hex)</label>
            <div className="flex gap-2">
              <input type="text" value={formData.messageHash} onChange={(e) => updateFormData("messageHash", e.target.value)} className="flex-1 border border-gray-300 rounded-md px-3 py-2 text-sm font-mono" placeholder="Enter message hash or generate random" />
              <button onClick={() => generateRandom("messageHash")} className="bg-gray-500 hover:bg-gray-700 text-white text-xs px-3 py-2 rounded">
                Generate Random
              </button>
            </div>
            {formData.messageText && <p className="text-xs text-gray-500 mt-1">Auto-generated from message text above</p>}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Nonce (32 bytes hex) - Optional</label>
            <div className="flex gap-2">
              <input type="text" value={formData.nonce} onChange={(e) => updateFormData("nonce", e.target.value)} className="flex-1 border border-gray-300 rounded-md px-3 py-2 text-sm font-mono" placeholder="Leave empty for deterministic nonce or generate random" />
              <button onClick={() => generateRandom("nonce")} className="bg-gray-500 hover:bg-gray-700 text-white text-xs px-3 py-2 rounded">
                Generate Random
              </button>
            </div>
          </div>
        </div>

        <button onClick={handleGenerateSignature} className="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded mt-4">
          Generate Signature
        </button>

        {results.generatedSignature && (
          <div className="mt-4">
            <h3 className="font-semibold">Generated Signature:</h3>
            <div className="text-sm font-mono bg-gray-100 p-2 rounded mt-2">
              <p>
                <strong>r:</strong> {bytesToHex(results.generatedSignature.r)}
              </p>
              <p>
                <strong>s:</strong> {bytesToHex(results.generatedSignature.s)}
              </p>
              <p className="mt-2">
                <strong>Full Signature (r+s):</strong> <span className="break-all">{signatureToFullHex(results.generatedSignature)}</span>
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Signature Verification Section */}
      <div className="bg-white shadow-lg rounded-lg p-6 mb-6">
        <h2 className="text-xl font-semibold mb-4">3. Verify EOTS Signature</h2>

        <div className="grid grid-cols-1 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Public Key (33 bytes hex - compressed)</label>
            <input type="text" value={formData.publicKey} onChange={(e) => updateFormData("publicKey", e.target.value)} className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm font-mono" placeholder="Enter public key" />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Signature R (32 bytes hex)</label>
              <input type="text" value={formData.signatureR} onChange={(e) => updateFormData("signatureR", e.target.value)} className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm font-mono" placeholder="Enter signature R value" />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Signature S (32 bytes hex)</label>
              <input type="text" value={formData.signatureS} onChange={(e) => updateFormData("signatureS", e.target.value)} className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm font-mono" placeholder="Enter signature S value" />
            </div>
          </div>
        </div>

        <button onClick={handleVerifySignature} className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded mt-4">
          Verify Signature
        </button>

        {results.verificationResult !== null && (
          <div className={`mt-4 p-3 rounded ${results.verificationResult ? "bg-green-100 text-green-800" : "bg-red-100 text-red-800"}`}>
            <p className="font-semibold">Verification Result: {results.verificationResult ? "VALID" : "INVALID"}</p>
          </div>
        )}
      </div>

      {/* Private Key Extraction Section */}
      <div className="bg-white shadow-lg rounded-lg p-6 mb-6">
        <h2 className="text-xl font-semibold mb-4">4. Extract Private Key from Nonce Reuse</h2>

        <div className="grid grid-cols-1 gap-4">
          <div>
            <h3 className="font-medium text-gray-800 mb-2">First Signature:</h3>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">R1</label>
                <input type="text" value={formData.signature1R} onChange={(e) => updateFormData("signature1R", e.target.value)} className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm font-mono" placeholder="Enter R value for signature 1" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">S1</label>
                <input type="text" value={formData.signature1S} onChange={(e) => updateFormData("signature1S", e.target.value)} className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm font-mono" placeholder="Enter S value for signature 1" />
              </div>
            </div>
            <div className="mt-2">
              <label className="block text-sm font-medium text-gray-700 mb-1">Message Hash 1</label>
              <div className="flex gap-2">
                <input type="text" value={formData.messageHash1} onChange={(e) => updateFormData("messageHash1", e.target.value)} className="flex-1 border border-gray-300 rounded-md px-3 py-2 text-sm font-mono" placeholder="Enter message hash for signature 1" />
                <button onClick={() => generateRandom("messageHash1")} className="bg-gray-500 hover:bg-gray-700 text-white text-xs px-3 py-2 rounded">
                  Generate Random
                </button>
              </div>
            </div>
          </div>

          <div>
            <h3 className="font-medium text-gray-800 mb-2">Second Signature:</h3>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">R2</label>
                <input type="text" value={formData.signature2R} onChange={(e) => updateFormData("signature2R", e.target.value)} className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm font-mono" placeholder="Enter R value for signature 2" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">S2</label>
                <input type="text" value={formData.signature2S} onChange={(e) => updateFormData("signature2S", e.target.value)} className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm font-mono" placeholder="Enter S value for signature 2" />
              </div>
            </div>
            <div className="mt-2">
              <label className="block text-sm font-medium text-gray-700 mb-1">Message Hash 2</label>
              <div className="flex gap-2">
                <input type="text" value={formData.messageHash2} onChange={(e) => updateFormData("messageHash2", e.target.value)} className="flex-1 border border-gray-300 rounded-md px-3 py-2 text-sm font-mono" placeholder="Enter message hash for signature 2" />
                <button onClick={() => generateRandom("messageHash2")} className="bg-gray-500 hover:bg-gray-700 text-white text-xs px-3 py-2 rounded">
                  Generate Random
                </button>
              </div>
            </div>
          </div>
        </div>

        <button onClick={handleExtractPrivateKey} className="bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded mt-4">
          Extract Private Key
        </button>

        {results.extractedPrivateKey && (
          <div className="mt-4">
            <h3 className="font-semibold">Extracted Private Key:</h3>
            <p className="text-sm font-mono bg-gray-100 p-2 rounded break-all">{results.extractedPrivateKey}</p>
            {results.taprootAddress && (
              <>
                <h3 className="font-semibold mt-2">Taproot Address:</h3>
                <p className="text-sm font-mono bg-gray-100 p-2 rounded break-all">{results.taprootAddress}</p>
              </>
            )}
          </div>
        )}
      </div>

      {/* Action Buttons */}
      <div className="text-center space-x-4">
        {/* <button onClick={handleRunTests} className="bg-purple-600 hover:bg-purple-800 text-white font-bold py-3 px-6 rounded-lg">
          🧪 Run Tests
        </button> */}
        <button onClick={handleRefresh} className="bg-gray-600 hover:bg-gray-800 text-white font-bold py-3 px-6 rounded-lg">
          🔄 Refresh All Fields
        </button>
      </div>

      {/* Information Section */}
      <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-6 mt-6">
        <h2 className="text-lg font-semibold text-yellow-800 mb-2">⚠️ Security Notice</h2>
        <p className="text-yellow-700 text-sm">EOTS (Extractable One-Time Signatures) are designed to reveal the private key if the same nonce is used twice. This is a feature, not a bug! Never reuse nonces in production systems. This demo is for testing purposes only.</p>
      </div>
    </div>
  );
}
