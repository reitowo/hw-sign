# Hardware-Bound Authentication System

Minimum Prototype Verification

## Overview

Binding login sessions to a pair of asymmetric keys in the device's hardware security module that cannot be exported, fundamentally preventing token theft or unauthorized use on other devices.

## Design

### Hardware Key Binding
- Hardware security module directly generates key pairs, private key cannot be exported
- Each request is verified through signatures

### Fallback Mechanism
Hardware binding is preferred, but when hardware security is unavailable, the system will degrade:
- Windows: System version too old, TPM doesn't exist or is disabled in BIOS
- Android: System version too old, neither TEE nor StrongBox exists

In these cases, login state is not protected by hardware keys, but normal usage is not affected

### Decoupled Process
- Agnostic to login state implementation, such as Cookies or various application Token systems
- Separated from login flow, which can use more secure authentication like WebAuthn

## Technical Implementation

### Key Architecture

#### Hardware Keys (Device Binding)
- Non-extractable cryptographic key pairs stored in hardware
- New key generated for each login session
- Dedicated to signing temporary keys
- Associated with login state, not user accounts

#### Temporary Keys (Memory-Only)
- Cryptographic key pairs stored only in memory to improve performance
- Signed by hardware keys to verify authenticity
- Used for regular API request signatures or ECDH key negotiation
- Supports rotation and regeneration (app restart/session expiry)

### Algorithm Priority and Format Requirements

#### Hardware Key Type Priority
1. ED25519
2. ECDSA (P-256) (secp256r1) - identified as `ecdsa-p256`
3. RSA-PSS (2048) - identified as `rsa-2048`

#### Temporary Key Type Priority
1. ECDH (P-256) - identified as `ecdh-p256` (for key negotiation)
2. ECDSA (P-256) - identified as `ecdsa-p256`
3. RSA-PSS (2048) - identified as `rsa-2048`

### Platform-Specific Implementation

#### Browser (Web Crypto API)
- Uses SubtleCrypto API
- IndexedDB-based key reference storage (non-exportable)

Example implementation: `hw-sign-browser/src/services/authService.ts`

#### Windows (CNG/NCrypt)
- Uses Windows CryptoNG (NCrypt) API
- TPM-based key storage

Example implementation: `hw-sign-win/main.cpp`

#### Apple (Secure Enclave)
- Uses SecKey API
- Secure Enclave-based key storage

Example implementation: `hw-sign-apple/hw-sign-apple/Services/AuthService.swift`

#### Android (Keystore)
- Uses Android Keystore API
- TEE / StrongBox-based key storage

Example implementation: `hw-sign-android/app/src/main/java/fan/ovo/hwsign/AuthService.kt`

### Example API Protocol Specification

#### Authentication Flow

1. Registration (POST /register)
   - Standard user registration, without hardware binding
   ```json
   {
     "username": "string",
     "password": "string"
   }
   ```

2. Hardware-Bound Login (POST /login)
   - Request Headers:
     - `x-rpc-sec-bound-token-hw-pub`: Hardware public key (base64 encoded)
     - `x-rpc-sec-bound-token-hw-pub-type`: Key algorithm ("ecdsa-p256", "rsa-2048")
   - Request Body:
   ```json
   {
     "username": "string",
     "password": "string"
   }
   ```
   - Response:
   ```json
   {
     "token": "string"
   }
   ```

3. Authenticated API Request (GET /authenticated)
   Common Request Headers:
   - `Authorization: Bearer <token>`
   - `x-rpc-sec-bound-token-data`: Timestamp+RandomHex string
   - `x-rpc-sec-bound-token-data-sig`: Request signature

   For New Temporary Keys:
   - `x-rpc-sec-bound-token-accel-pub`: Temporary public key
   - `x-rpc-sec-bound-token-accel-pub-type`: Key algorithm type
   - `x-rpc-sec-bound-token-accel-pub-sig`: Hardware-signed temporary key

   New Temporary Key Response Headers:
   - `x-rpc-sec-bound-token-accel-pub-id`: Temporary key ID
   - `x-rpc-sec-bound-token-accel-pub-expire`: Expiration as Unix timestamp in seconds

   For Existing Keys:
   - `x-rpc-sec-bound-token-accel-pub-id`: Temporary key ID

### Request Signatures

Format for `x-rpc-sec-bound-token-data` is `{Timestamp}-{32BytesRandomHex}`, ordered by security from high to low:

1. Random String with Redis
   - Signs random nonce
   - Stored in Redis to prevent replay attacks
   - Best security, requires Redis
   - Server uses each value only once, repeated use considered invalid
   - Server rejects requests where Timestamp < Now - TExpire

2. Request Body Hash
   - Signs SHA256 hash of request body
   - No additional storage needed
   - Requires access to original request body (may not apply to gRPC interfaces)

3. Timestamp
   - Signs current timestamp
   - Sets short expiration window
   - Simplest, slightly lower security

### Performance Optimization - ECDH Key Negotiation

For performance-sensitive scenarios, ECDH-negotiated shared keys with HMAC-SHA256 for high-performance signatures:

1. Initialization Process:
   - SDK generates temporary key pair (CliTmpPub/CliTmpPriv) during initialization
   - Hardware private key signs CliTmpPub (only once)
   - No need for hardware signing again during this program execution

2. Request Signature Process:
   - On first request, server generates temporary key pair (SrvTmpPub/SrvTmpPriv)
   - Server uses CliTmpPub+SrvTmpPriv to generate shared key HmacSecret via ECDH
   - Client uses SrvTmpPub+CliTmpPriv to generate the same HmacSecret via ECDH
   - Subsequent requests use HmacSecret to calculate HMAC-SHA256 signatures for better performance

#### Reference Parameters

When generating new temporary negotiation key pairs:
- `x-rpc-sec-bound-token-accel-pub`: Client temporary negotiation public key
- `x-rpc-sec-bound-token-accel-pub-type`: Client temporary negotiation public key type: `ecdh-p256`
- `x-rpc-sec-bound-token-accel-pub-sig`: Signature of client temporary negotiation public key generated with hardware key

When server returns new temporary negotiation public key:
- `x-rpc-sec-bound-token-accel-pub`: Server temporary negotiation public key
- `x-rpc-sec-bound-token-accel-pub-id`: Temporary negotiation public key ID, pointing to the negotiated symmetric key
- `x-rpc-sec-bound-token-accel-pub-expire`: Expiration Unix timestamp in seconds

Signature parameters in requests:
- `x-rpc-sec-bound-token-data`: Format is `{Timestamp}-{32BytesRandomHex}`
- `x-rpc-sec-bound-token-data-sig`: HMAC calculated with negotiated symmetric key on the above data
- `x-rpc-sec-bound-token-accel-pub-id`: Temporary public key ID

## Examples

All subfolders correspond to example implementations for each platform and can be directly opened as projects for compilation

## Compare to DBSC (Device Bound Session Credentials)

DBSC is also a cool solution with similar ideas. However, it is designed for Web Platform, and this repo use native abilities for all platforms. DBSC also doesn't sign all requests with hardware crypto keypairs, while this one will sign all requests.

> Note: Over 90% of the code was generated with AI assistance, but human verification ensures correctness
