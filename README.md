# EOTS (Extractable One-Time Signatures) TypeScript Implementation

A comprehensive implementation of EOTS (Extractable One-Time Signatures) with an interactive web interface. This implementation uses the secp256k1 elliptic curve for compatibility with Bitcoin and includes full support for signature generation, verification, and private key extraction.

## 🚀 Features

- **Key Generation**: Generate EOTS key pairs with secp256k1
- **Signature Generation**: Create EOTS signatures with nonce support
- **Signature Verification**: Verify EOTS signatures  
- **Private Key Extraction**: Extract private keys from nonce reuse
- **Bitcoin Integration**: Derive Taproot addresses from private keys
- **Interactive Web UI**: User-friendly interface with random value generation
- **TypeScript Support**: Full type safety and IDE support

## 🛠 Installation

```bash
# Clone the repository
git clone <repository-url>
cd eots-app

# Install dependencies
npm install

# Run the development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) to view the application.

## 📚 Core API

### Key Generation

```typescript
import { generateEOTSKeyPair } from '@/lib';

const keyPair = generateEOTSKeyPair();
console.log('Private Key:', bytesToHex(keyPair.privateKey));
console.log('Public Key:', bytesToHex(keyPair.publicKey));
```

### Signature Generation

```typescript
import { signEOTS } from '@/lib';

const signature = signEOTS(
  privateKey,    // Private key (32 bytes hex or Uint8Array)
  messageHash,   // Message hash (32 bytes hex or Uint8Array) 
  nonce          // Optional nonce (32 bytes hex or Uint8Array)
);

console.log('Signature R:', bytesToHex(signature.r));
console.log('Signature S:', bytesToHex(signature.s));
```

### Signature Verification

```typescript
import { verifyEOTS } from '@/lib';

const isValid = verifyEOTS(
  publicKey,     // Public key (65 bytes hex or Uint8Array)
  messageHash,   // Message hash (32 bytes hex or Uint8Array)
  signature      // EOTSSignature object
);

console.log('Signature valid:', isValid);
```

### Private Key Extraction

```typescript
import { extractPrivateKey } from '@/lib';

// When the same nonce is used for two different messages
const extractedKey = extractPrivateKey(
  signature1,    // First signature
  signature2,    // Second signature  
  messageHash1,  // First message hash
  messageHash2   // Second message hash
);

console.log('Extracted Private Key:', bytesToHex(extractedKey));
```

### Bitcoin Taproot Address

```typescript
import { deriveTaprootAddress } from '@/lib';

const address = deriveTaprootAddress(privateKey);
console.log('Taproot Address:', address);
```

## 🔧 Web Interface

The application provides a comprehensive web interface with four main sections:

### 1. Key Generation
- Generate new EOTS key pairs
- Display public key and Taproot address
- One-click key pair generation

### 2. Signature Generation  
- Input private key, message hash, and optional nonce
- Generate random values with one-click buttons
- Automatic public key derivation and Taproot address display
- Auto-fill verification form with generated signature

### 3. Signature Verification
- Input public key, message hash, and signature components
- Real-time validation feedback
- Clear visual indication of verification results

### 4. Private Key Extraction
- Input two signatures with the same nonce
- Demonstrate nonce reuse vulnerability
- Extract and display the original private key
- Show corresponding Taproot address

### 5. Utility Features
- **Random Generation**: One-click random value generation for all fields
- **Input Validation**: Real-time hex format validation
- **Error Handling**: Comprehensive error messages and validation
- **Refresh**: Clear all fields and start fresh
- **Responsive Design**: Works on desktop and mobile devices

## ⚠️ Security Considerations

**CRITICAL WARNING**: EOTS signatures are designed to reveal the private key when the same nonce is used twice. This is intentional behavior that makes EOTS suitable for specific use cases like:

- Penalty mechanisms in Layer 2 protocols
- Anti-equivocation systems
- Commitment schemes with punishment

### Important Security Notes:

1. **Never reuse nonces** - This will expose your private key
2. **Production Use** - This implementation is for development purposes
3. **Key Management** - Always use secure random number generation
4. **Input Validation** - Always validate inputs in production systems

## 🧪 Example Usage Scenarios

### Scenario 1: Normal EOTS Usage
```typescript
// 1. Generate key pair
const keyPair = generateEOTSKeyPair();

// 2. Sign message
const message1 = "Hello, EOTS!";
const hash1 = sha256(new TextEncoder().encode(message1));
const sig1 = signEOTS(keyPair.privateKey, hash1);

// 3. Verify signature
const isValid = verifyEOTS(keyPair.publicKey, hash1, sig1);
console.log('Valid:', isValid); // true
```

### Scenario 2: Nonce Reuse (Private Key Extraction)
```typescript
// Same private key, same nonce, different messages
const privateKey = generateRandomPrivateKey();
const nonce = generateRandomNonce();

const hash1 = generateRandomMessageHash();
const hash2 = generateRandomMessageHash();

const sig1 = signEOTS(privateKey, hash1, nonce);
const sig2 = signEOTS(privateKey, hash2, nonce); // Same nonce!

// Extract private key
const extractedKey = extractPrivateKey(sig1, sig2, hash1, hash2);
console.log('Original key:', privateKey);
console.log('Extracted key:', bytesToHex(extractedKey));
console.log('Match:', privateKey === bytesToHex(extractedKey)); // true
```

## 📁 Project Structure

```
src/
├── lib/
│   ├── types.ts         # TypeScript interfaces
│   ├── utils.ts         # Utility functions
│   ├── eots.ts          # Core EOTS implementation
│   └── index.ts         # Main exports
├── app/
│   ├── page.tsx         # Main application interface
│   ├── layout.tsx       # App layout
│   └── globals.css      # Global styles
└── ...
```

## 🔬 Technical Details

### Cryptographic Foundation
- **Curve**: secp256k1 (same as Bitcoin)
- **Hash Function**: SHA-256
- **Key Size**: 32 bytes (256 bits)
- **Signature Format**: (r, s) where each is 32 bytes

### Implementation Details
- **Deterministic Nonces**: Generated from private key + message hash when not provided
- **Input Validation**: Comprehensive validation for all cryptographic inputs  
- **Error Handling**: Descriptive error messages for debugging
- **Type Safety**: Full TypeScript support with strict typing

### Browser Compatibility
- Uses `@noble/secp256k1` for cryptographic operations
- Compatible with modern browsers supporting WebCrypto API
- No native dependencies - runs entirely in JavaScript

## 🧪 Testing

The implementation includes comprehensive validation:

- **Input Validation**: Hex format, length validation
- **Cryptographic Validation**: Valid curve points, non-zero values
- **Error Cases**: Invalid signatures, mismatched nonces
- **Edge Cases**: Zero values, boundary conditions

## 📖 References

- [EOTS Paper/Specification]
- [secp256k1 Curve Parameters](https://en.bitcoin.it/wiki/Secp256k1)
- [Bitcoin Taproot](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)

## 🤝 Contributing

Contributions are welcome! Please ensure:

1. All new features include proper TypeScript types
2. Cryptographic operations are properly tested
3. Security considerations are documented
4. Code follows the existing style conventions

## 📄 License

This project is for testing and development purposes. Please review and understand the cryptographic implementations before using in production systems.

---

**Disclaimer**: This implementation is provided for testing purposes. Always conduct thorough security audits before using cryptographic code in production systems. 