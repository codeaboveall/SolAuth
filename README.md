# SolAuth

![SolAuth Logo](solauth.png)

## Table of Contents

1. [Introduction](#introduction)
2. [Design Philosophy](#design-philosophy)
3. [Threat Model](#threat-model)
4. [High-Level Flow](#high-level-flow)
5. [API Overview](#api-overview)
6. [Cryptographic Details](#cryptographic-details)
7. [Session Management](#session-management)
8. [Comparison with Other Authentication Systems](#comparison-with-other-authentication-systems)
9. [Usage Examples](#usage-examples)
10. [Security Considerations](#security-considerations)
11. [Roadmap](#roadmap)
12. [License](#license)

---

## Introduction

SolAuth is a wallet-based authentication system designed for applications built on the Solana blockchain. It provides a mechanism for users to authenticate by proving cryptographic control of a Solana wallet address, eliminating the need for traditional username and password credentials.

### Problem Statement

Traditional authentication systems rely on shared secrets (passwords) or delegated trust (OAuth providers). These approaches present fundamental mismatches for blockchain-native applications:

**Password-based authentication** requires users to create and manage additional credentials for each service. This introduces several problems:
- Credential databases become high-value targets for attackers
- Users must trust services to properly hash and store passwords
- Password reuse across services creates cascading security failures
- Account recovery mechanisms often undermine security models
- No cryptographic proof of identity is established

**OAuth and federated identity** delegate authentication to third-party providers (Google, GitHub, etc.). While this reduces password management burden, it introduces different problems:
- Users must trust and maintain accounts with centralized identity providers
- Services must trust OAuth providers to correctly authenticate users
- OAuth providers can revoke access, censor users, or be compelled to do so
- The user's blockchain identity (wallet address) remains disconnected from their application identity
- No direct cryptographic relationship exists between the user and the service

For applications operating in the Solana ecosystem, users already possess a cryptographic identity: their wallet keypair. This wallet represents:
- Proof of identity through signature capability
- Control over on-chain assets and program interactions
- An existing security model users understand and manage
- No reliance on external identity providers

SolAuth formalizes a protocol for using wallet signatures as an authentication primitive, allowing applications to authenticate users based on cryptographic proof rather than shared secrets or delegated trust.

### Core Concept

SolAuth implements a challenge-response authentication flow:

1. The application server generates a unique challenge (nonce)
2. The user signs this challenge with their wallet's private key
3. The server verifies the signature against the claimed public key
4. Upon successful verification, the server establishes an authenticated session

This flow proves the user controls the private key corresponding to a specific wallet address without exposing the private key itself. The authenticated session can then be used for subsequent requests without requiring repeated signatures.

### Use Cases

SolAuth is designed for a broad range of applications:

- **Web applications**: Decentralized exchanges, NFT marketplaces, DeFi dashboards, and DAOs requiring user authentication
- **API services**: Rate limiting, access control, and usage tracking based on wallet identity
- **Administrative interfaces**: Internal tools requiring Solana wallet-based access control
- **CLI tools**: Command-line applications that need to authenticate against remote services
- **Multi-signature coordinators**: Systems requiring proof of co-signer identity
- **Audit and compliance systems**: Applications requiring verified wallet ownership for regulatory purposes

### Non-Goals

SolAuth is explicitly not:

- A permission or authorization framework (it proves identity, not access rights)
- A replacement for on-chain program access control
- A key management system
- A wallet implementation
- A custody solution
- A system for delegating signing authority

---

## Design Philosophy

SolAuth is built on several core principles that inform its architecture and implementation.

### Non-Custodial Identity

Users retain complete control of their private keys at all times. SolAuth never requires users to share, export, or otherwise compromise their private keys. Authentication is achieved through signatures, which prove knowledge of a private key without revealing it. The server never possesses the ability to impersonate a user or execute actions on their behalf beyond what is explicitly authorized through the session mechanism.

This principle extends to the session itself. While an authenticated session allows the server to associate requests with a wallet address, it does not grant the server any blockchain-level authority. The server cannot sign transactions, transfer assets, or interact with on-chain programs using the user's identity.

### Minimal Trust Assumptions

SolAuth minimizes the trust placed in any single component:

- **Client trust**: Clients must trust that the server will honor the authentication session and not abuse the established identity. This is unavoidable in any authentication system where the server provides a service.

- **Server trust**: Servers must trust the Solana validator network to correctly validate signatures. This is equivalent to the trust assumption of any Solana program.

- **No external dependencies**: SolAuth does not require trust in external identity providers, certificate authorities, or third-party services. The only cryptographic trust anchor is the Solana signature verification algorithm.

- **Open source implementation**: The reference implementation is open source, allowing independent security review and verification of claims.

### Replay Protection

Every authentication challenge is single-use and time-limited. The server generates a cryptographically random nonce for each authentication attempt. Once a signature over a particular nonce is verified, that nonce is invalidated and cannot be reused. Expired nonces are also rejected.

This prevents several attack vectors:
- An attacker cannot reuse a captured signature to authenticate as the user
- An attacker cannot replay old signatures if they intercept network traffic
- The time-limited nature of nonces bounds the window of vulnerability

### Explicit User Consent

Each authentication attempt requires explicit user action. The user must review the authentication request in their wallet interface and actively approve the signature. This ensures users are aware when they are authenticating to a service and can make informed decisions about when to grant access.

The message format includes human-readable context (domain, timestamp, purpose) so users can verify they are authenticating to the correct service. Well-designed wallet interfaces will display this information clearly before prompting for signature approval.

### Domain Binding

Authentication challenges are bound to the specific domain or service identifier requesting authentication. This prevents an attacker from obtaining a signature intended for one service and using it to authenticate to a different service (cross-domain signature reuse).

The domain binding is included in the signed message payload and verified by the server. If a signature was generated for domain A, it cannot be used to authenticate to domain B, even if the attacker can intercept the signature.

### Composability

SolAuth is designed as a protocol specification rather than a monolithic implementation. This allows:

- **Framework independence**: SolAuth can be implemented in any programming language and web framework
- **Deployment flexibility**: The protocol can be deployed on traditional web servers, serverless platforms, or edge computing infrastructure
- **Client diversity**: Any client capable of requesting signatures from a Solana wallet can use SolAuth
- **Custom extensions**: Applications can extend the protocol with additional fields or verification steps while maintaining core compatibility

### Stateless Option

While SolAuth supports traditional stateful sessions, it is designed to also function in stateless environments using cryptographically signed tokens (JWT). This allows horizontal scaling without shared session storage and supports serverless deployment models.

The stateless design does introduce trade-offs in revocation capabilities, which are discussed in detail in the Session Management section.

---

## Threat Model

This section describes the security properties SolAuth provides and the attacks it is designed to prevent. It also explicitly documents attacks that SolAuth does not defend against and must be addressed at other layers.

### Threats Mitigated

#### Replay Attacks

**Attack**: An attacker intercepts a valid authentication signature and attempts to reuse it to authenticate as the victim.

**Mitigation**: Each challenge nonce is single-use and tracked by the server. After successful verification, the nonce is invalidated. Subsequent attempts to use the same signature will fail because the nonce has been consumed. Additionally, nonces have a limited validity window (typically 5-15 minutes), after which they are rejected even if unused.

**Implementation requirement**: Servers must maintain a nonce registry that persists across server restarts for the duration of the nonce validity period. For distributed deployments, this registry must be shared across all server instances.

#### Signature Reuse Across Domains

**Attack**: An attacker operating a malicious service (domain A) tricks a user into signing an authentication challenge. The attacker then attempts to use this signature to authenticate as the user to a different legitimate service (domain B).

**Mitigation**: The signed message includes the domain or service identifier. The verifying server checks that the domain in the signed message matches its own domain. Signatures generated for one domain are rejected by other domains.

**Implementation requirement**: The domain binding must be prominently displayed in the wallet interface so users can verify they are authenticating to the expected service.

#### Phishing Attacks (Partial Mitigation)

**Attack**: An attacker creates a fake version of a legitimate service and attempts to trick users into authenticating, capturing their wallet address and potentially using the authenticated session to gather information or perform unauthorized actions.

**Mitigation**: SolAuth includes the domain in the signed message, which should be displayed to the user. Careful users can verify they are authenticating to the correct domain. However, this requires user vigilance and depends on wallet interface design.

**Limitations**: SolAuth cannot prevent phishing if users do not verify the domain, or if the wallet interface does not clearly display the domain. This is analogous to SSL/TLS: the technology provides the mechanism for verification, but user behavior determines effectiveness.

#### Man-in-the-Middle Attacks on Authentication

**Attack**: An attacker intercepts the authentication flow and attempts to modify the challenge, signature, or verification response.

**Mitigation**: The signature cryptographically binds the challenge to the user's wallet. Any modification to the challenge or signature will cause verification to fail. The attacker cannot forge a valid signature without access to the private key.

**Implementation requirement**: The authentication endpoint must be served over TLS to prevent interception of the challenge or session token. While the signature itself is tamper-evident, an attacker who intercepts the resulting session token can use it to impersonate the user.

#### Session Hijacking (Partial Mitigation)

**Attack**: An attacker steals a valid session token (cookie, JWT, etc.) and uses it to impersonate the authenticated user.

**Mitigation**: SolAuth provides mechanisms to limit session lifetime, scope, and revocation. Short-lived sessions reduce the window of vulnerability. Session binding to IP address or user agent provides additional defense in depth.

**Limitations**: SolAuth cannot prevent session hijacking if the session token is stolen. This is a general problem with any session-based authentication system. Applications must use TLS, HttpOnly cookies, and other standard web security practices.

#### Credential Stuffing and Password Attacks

**Attack**: Attackers use lists of compromised passwords to attempt authentication to multiple services.

**Mitigation**: SolAuth eliminates passwords entirely. There are no shared secrets to steal, compromise, or reuse. Authentication requires possession of the private key, which is never transmitted to the server.

### Threats Not Mitigated

These attacks are outside the scope of SolAuth and must be addressed by other security layers.

#### Private Key Compromise

If an attacker gains access to a user's private key, they can sign arbitrary messages and authenticate as that user. SolAuth cannot detect or prevent this. Wallet security, key management, and hardware wallet usage are the user's responsibility.

#### Client-Side Attacks

SolAuth does not protect against attacks on the client device:
- Malware that captures signatures or session tokens
- Browser extensions that intercept wallet API calls
- XSS attacks that steal session tokens
- Clickjacking attacks that trick users into signing malicious messages

These must be addressed through standard web security practices (CSP, XSS prevention, frame busting) and client-side security (antivirus, secure browsing practices).

#### Server-Side Vulnerabilities

SolAuth does not protect against:
- SQL injection, command injection, or other server-side vulnerabilities
- Server compromise that exposes session storage or allows session forgery
- Business logic flaws in the application
- Denial of service attacks

Standard secure development practices and infrastructure security are required.

#### Social Engineering

SolAuth cannot prevent users from being tricked into signing messages they do not understand, or authenticating to malicious services. User education and clear wallet interfaces are essential.

#### Smart Contract Exploitation

SolAuth authenticates users to web applications, not on-chain programs. It does not provide any protection against smart contract vulnerabilities, reentrancy attacks, or other on-chain security issues.

#### Time-of-Check to Time-of-Use (TOCTOU) Issues

If an application makes authorization decisions based on on-chain state (token balance, NFT ownership, etc.), there is a race condition between the authentication check and the on-chain state check. An attacker could authenticate, transfer assets, and then execute an action that should have required those assets.

Applications must verify authorization criteria at the time of each action, not just at authentication time.

---

## High-Level Flow

This section describes the complete authentication flow from initial request to established session.

### Authentication Sequence

```
┌──────┐                          ┌──────┐                          ┌──────┐
│Client│                          │Server│                          │Wallet│
└───┬──┘                          └───┬──┘                          └───┬──┘
    │                                 │                                 │
    │  1. Request Challenge            │                                 │
    │─────────────────────────────────>│                                 │
    │                                 │                                 │
    │                                 │  2. Generate Nonce              │
    │                                 │────┐                            │
    │                                 │    │                            │
    │                                 │<───┘                            │
    │                                 │                                 │
    │  3. Return Challenge             │                                 │
    │<─────────────────────────────────│                                 │
    │                                 │                                 │
    │  4. Request Signature            │                                 │
    │─────────────────────────────────────────────────────────────────>│
    │                                 │                                 │
    │                                 │                                 │
    │                                 │  5. User Reviews & Approves     │
    │                                 │                 ┌───────────────┤
    │                                 │                 │               │
    │                                 │                 └──────────────>│
    │                                 │                                 │
    │  6. Return Signature             │                                 │
    │<─────────────────────────────────────────────────────────────────┤
    │                                 │                                 │
    │  7. Submit Signature             │                                 │
    │─────────────────────────────────>│                                 │
    │                                 │                                 │
    │                                 │  8. Verify Signature            │
    │                                 │────┐                            │
    │                                 │    │                            │
    │                                 │<───┘                            │
    │                                 │                                 │
    │                                 │  9. Create Session              │
    │                                 │────┐                            │
    │                                 │    │                            │
    │                                 │<───┘                            │
    │                                 │                                 │
    │  10. Return Session Token        │                                 │
    │<─────────────────────────────────│                                 │
    │                                 │                                 │
```

### Detailed Step Description

#### Step 1: Request Challenge

The client initiates authentication by requesting a challenge from the server. This request includes:

- The wallet address (public key) the user wishes to authenticate with
- Optional: metadata such as user agent, client type, or requested session parameters

The client does not send any secrets at this stage. The public key is not sensitive information.

#### Step 2: Generate Nonce

The server receives the challenge request and generates a unique nonce. The nonce must be:

- Cryptographically random (minimum 128 bits of entropy)
- Globally unique within the nonce validity window
- Associated with the requesting public key
- Time-stamped for expiration tracking

The server stores the nonce in its nonce registry with an expiration timestamp. The nonce is marked as unused.

#### Step 3: Return Challenge

The server returns the challenge to the client. The response includes:

- The nonce
- The domain/service identifier
- The nonce expiration time
- Optional: additional context (purpose, requested session duration)

The client will use this information to construct the message to be signed.

#### Step 4: Request Signature

The client constructs a message incorporating the challenge data:

```
SolAuth Authentication Request

Domain: example.com
Nonce: 7f8d9e3a2b1c4f5d6e7a8b9c0d1e2f3g4h5i6j7k8l9m0n1o2p3q4r5s6t7u8v9w0
Issued At: 2025-01-03T10:30:00Z
Expires At: 2025-01-03T10:45:00Z

By signing this message, you are authenticating to example.com.
```

This message is passed to the wallet interface for signing. The exact mechanism depends on the wallet implementation (browser extension, mobile wallet, hardware wallet).

#### Step 5: User Reviews and Approves

The wallet displays the message to the user. A well-designed wallet interface will clearly show:

- The domain requesting authentication
- The current timestamp
- A warning if the request is from an unknown or suspicious domain
- A clear approve/reject option

The user reviews this information and decides whether to approve the signature.

#### Step 6: Return Signature

If the user approves, the wallet signs the message with the private key and returns the signature to the client. The signature is a byte array that proves the signer possessed the private key corresponding to the public key.

#### Step 7: Submit Signature

The client submits the signature to the server along with:

- The public key
- The nonce
- The complete message that was signed
- Optional: any additional authentication parameters

#### Step 8: Verify Signature

The server performs several verification steps:

1. **Nonce validation**: Check that the nonce exists in the registry, has not been used, and has not expired
2. **Message reconstruction**: Reconstruct the expected message from the nonce and server state
3. **Message comparison**: Verify that the submitted message matches the expected message
4. **Signature verification**: Cryptographically verify that the signature is valid for the message and public key
5. **Domain validation**: Confirm that the domain in the message matches the server's domain

If any verification step fails, the authentication is rejected.

#### Step 9: Create Session

Upon successful verification, the server:

1. Marks the nonce as used (preventing replay)
2. Creates a new session associated with the authenticated public key
3. Generates a session token (opaque token or JWT)
4. Stores session metadata (creation time, expiration, IP address)

#### Step 10: Return Session Token

The server returns the session token to the client. The client stores this token (typically in a cookie or local storage) and includes it in subsequent requests to prove authentication.

### Session-Based Request Flow

Once authenticated, subsequent requests follow a simpler pattern:

```
┌──────┐                          ┌──────┐
│Client│                          │Server│
└───┬──┘                          └───┬──┘
    │                                 │
    │  Request + Session Token        │
    │─────────────────────────────────>│
    │                                 │
    │                                 │  Validate Token
    │                                 │────┐
    │                                 │    │
    │                                 │<───┘
    │                                 │
    │  Response                        │
    │<─────────────────────────────────│
    │                                 │
```

The server validates the session token on each request and associates the request with the authenticated wallet address.

---

## API Overview

This section documents the core API endpoints for SolAuth. These are reference specifications; actual implementations may add additional endpoints or fields as needed.

### Endpoint: Request Challenge

**Method**: `POST /auth/challenge`

**Description**: Request a new authentication challenge for a given wallet address.

**Request Body**:
```json
{
  "publicKey": "7j8sKQN7ZHCxrz3YMwjXJ4mKqPvCt9xvR2hF5nE8pLmN",
  "metadata": {
    "userAgent": "Mozilla/5.0...",
    "clientType": "web",
    "requestedSessionDuration": 3600
  }
}
```

**Request Fields**:
- `publicKey` (required, string): Base58-encoded Solana public key
- `metadata` (optional, object): Additional context provided by the client

**Response** (200 OK):
```json
{
  "challenge": {
    "nonce": "7f8d9e3a2b1c4f5d6e7a8b9c0d1e2f3g4h5i6j7k8l9m0n1o2p3q4r5s6t7u8v9w0",
    "domain": "api.example.com",
    "issuedAt": "2025-01-03T10:30:00Z",
    "expiresAt": "2025-01-03T10:45:00Z",
    "message": "SolAuth Authentication Request\n\nDomain: api.example.com\nNonce: 7f8d9e3a2b1c4f5d6e7a8b9c0d1e2f3g4h5i6j7k8l9m0n1o2p3q4r5s6t7u8v9w0\nIssued At: 2025-01-03T10:30:00Z\nExpires At: 2025-01-03T10:45:00Z\n\nBy signing this message, you are authenticating to api.example.com."
  }
}
```

**Response Fields**:
- `challenge.nonce` (string): Unique nonce for this authentication attempt
- `challenge.domain` (string): Domain of the service
- `challenge.issuedAt` (string): ISO 8601 timestamp when the challenge was issued
- `challenge.expiresAt` (string): ISO 8601 timestamp when the challenge expires
- `challenge.message` (string): Complete message to be signed by the user

**Error Responses**:
- `400 Bad Request`: Invalid public key format
- `429 Too Many Requests`: Rate limit exceeded
- `503 Service Unavailable`: Server cannot generate challenges at this time

### Endpoint: Verify Signature

**Method**: `POST /auth/verify`

**Description**: Submit a signed challenge for verification and receive a session token.

**Request Body**:
```json
{
  "publicKey": "7j8sKQN7ZHCxrz3YMwjXJ4mKqPvCt9xvR2hF5nE8pLmN",
  "nonce": "7f8d9e3a2b1c4f5d6e7a8b9c0d1e2f3g4h5i6j7k8l9m0n1o2p3q4r5s6t7u8v9w0",
  "signature": "3yZe7d1u8qH4kL2f9J8xW6vT1pN5mB7rC3gV2nM9hK4sF8wE6tY7uI9oP5aS2dQ3zX7cR1vB4nM6lK8jH3gT5fE9dW2qY4uI7oP1aS6",
  "message": "SolAuth Authentication Request\n\nDomain: api.example.com\nNonce: 7f8d9e3a2b1c4f5d6e7a8b9c0d1e2f3g4h5i6j7k8l9m0n1o2p3q4r5s6t7u8v9w0\nIssued At: 2025-01-03T10:30:00Z\nExpires At: 2025-01-03T10:45:00Z\n\nBy signing this message, you are authenticating to api.example.com."
}
```

**Request Fields**:
- `publicKey` (required, string): Base58-encoded Solana public key
- `nonce` (required, string): The nonce from the challenge
- `signature` (required, string): Base58-encoded signature
- `message` (required, string): The exact message that was signed

**Response** (200 OK):
```json
{
  "session": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "publicKey": "7j8sKQN7ZHCxrz3YMwjXJ4mKqPvCt9xvR2hF5nE8pLmN",
    "issuedAt": "2025-01-03T10:30:15Z",
    "expiresAt": "2025-01-03T11:30:15Z"
  }
}
```

**Response Fields**:
- `session.token` (string): Session token to be included in subsequent requests
- `session.publicKey` (string): The authenticated public key
- `session.issuedAt` (string): ISO 8601 timestamp when the session was created
- `session.expiresAt` (string): ISO 8601 timestamp when the session expires

**Error Responses**:
- `400 Bad Request`: Invalid request format or missing fields
- `401 Unauthorized`: Signature verification failed
  - `INVALID_SIGNATURE`: Signature is cryptographically invalid
  - `NONCE_NOT_FOUND`: Nonce does not exist or has expired
  - `NONCE_ALREADY_USED`: Nonce has been used in a previous authentication
  - `MESSAGE_MISMATCH`: Submitted message does not match expected message
  - `DOMAIN_MISMATCH`: Domain in message does not match server domain
- `429 Too Many Requests`: Rate limit exceeded

### Endpoint: Get Session

**Method**: `GET /auth/session`

**Description**: Retrieve information about the current authenticated session.

**Request Headers**:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response** (200 OK):
```json
{
  "session": {
    "publicKey": "7j8sKQN7ZHCxrz3YMwjXJ4mKqPvCt9xvR2hF5nE8pLmN",
    "issuedAt": "2025-01-03T10:30:15Z",
    "expiresAt": "2025-01-03T11:30:15Z",
    "lastActivity": "2025-01-03T10:45:22Z"
  }
}
```

**Response Fields**:
- `session.publicKey` (string): The authenticated public key
- `session.issuedAt` (string): When the session was created
- `session.expiresAt` (string): When the session expires
- `session.lastActivity` (string): Timestamp of most recent activity

**Error Responses**:
- `401 Unauthorized`: No valid session token provided
- `403 Forbidden`: Session has expired

### Endpoint: Revoke Session

**Method**: `POST /auth/revoke`

**Description**: Explicitly revoke the current session, logging the user out.

**Request Headers**:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Request Body** (optional):
```json
{
  "reason": "user_logout"
}
```

**Response** (200 OK):
```json
{
  "revoked": true,
  "publicKey": "7j8sKQN7ZHCxrz3YMwjXJ4mKqPvCt9xvR2hF5nE8pLmN"
}
```

**Response Fields**:
- `revoked` (boolean): Confirmation that the session was revoked
- `publicKey` (string): The public key associated with the revoked session

**Error Responses**:
- `401 Unauthorized`: No valid session token provided
- `404 Not Found`: Session does not exist or was already revoked

### Request Authentication

All endpoints except `/auth/challenge` and `/auth/verify` require authentication. The session token should be included in one of the following ways:

**Authorization Header** (preferred):
```
Authorization: Bearer <token>
```

**Cookie** (for web applications):
```
Cookie: solauth_token=<token>
```

### Rate Limiting

All authentication endpoints should implement rate limiting to prevent abuse:

- Challenge endpoint: 10 requests per minute per IP address
- Verify endpoint: 5 requests per minute per public key
- Session endpoints: 60 requests per minute per session

Implementations should return HTTP 429 (Too Many Requests) when rate limits are exceeded, with a `Retry-After` header indicating when the client can retry.

---

## Cryptographic Details

This section provides technical details about the cryptographic operations underlying SolAuth.

### Signature Algorithm

SolAuth uses the Ed25519 signature algorithm, which is the standard signature scheme for Solana. Ed25519 is a Schnorr signature variant using Edwards curves.

**Key properties**:
- Public key size: 32 bytes
- Signature size: 64 bytes
- Security level: 128 bits
- Deterministic signatures (no random nonce required during signing)
- Fast verification

### Public Key Format

Public keys are 32-byte Ed25519 points. In SolAuth API calls and messages, public keys are encoded in base58 (Bitcoin-style base58check without the checksum).

Example public key:
```
7j8sKQN7ZHCxrz3YMwjXJ4mKqPvCt9xvR2hF5nE8pLmN
```

This decodes to 32 bytes. Implementations must validate that:
- The base58 string decodes successfully
- The result is exactly 32 bytes
- The bytes represent a valid point on the Ed25519 curve

### Signature Format

Signatures are 64-byte Ed25519 signatures, also encoded in base58 for transmission.

Example signature:
```
3yZe7d1u8qH4kL2f9J8xW6vT1pN5mB7rC3gV2nM9hK4sF8wE6tY7uI9oP5aS2dQ3zX7cR1vB4nM6lK8jH3gT5fE9dW2qY4uI7oP1aS6
```

### Message Format

The message to be signed follows a specific structure to ensure consistency and prevent ambiguity. The canonical format is:

```
SolAuth Authentication Request

Domain: <domain>
Nonce: <nonce>
Issued At: <timestamp>
Expires At: <timestamp>

By signing this message, you are authenticating to <domain>.
```

**Important considerations**:

1. **Line endings**: Messages use Unix-style line endings (`\n`). Windows-style line endings (`\r\n`) will cause verification to fail.

2. **Whitespace**: Spacing must be exact. There are no extra spaces before or after field values.

3. **Encoding**: Messages are UTF-8 encoded before signing.

4. **Field order**: Fields must appear in the exact order specified. Reordering will cause verification to fail.

5. **Field values**:
   - `<domain>`: The fully qualified domain name (no protocol, no path)
   - `<nonce>`: Hexadecimal or base58 string, minimum 32 characters
   - `<timestamp>`: ISO 8601 format with UTC timezone (suffix `Z`)

Example message:
```
SolAuth Authentication Request

Domain: api.example.com
Nonce: 7f8d9e3a2b1c4f5d6e7a8b9c0d1e2f3g4h5i6j7k8l9m0n1o2p3q4r5s6t7u8v9w0
Issued At: 2025-01-03T10:30:00Z
Expires At: 2025-01-03T10:45:00Z

By signing this message, you are authenticating to api.example.com.
```

### Signature Verification

The signature verification process is:

1. **Decode inputs**: Base58-decode the public key and signature
2. **Encode message**: UTF-8 encode the message string to bytes
3. **Verify**: Use Ed25519 verification with the public key, message bytes, and signature

Pseudocode:
```
function verifySignature(publicKeyBase58, messageString, signatureBase58):
    publicKeyBytes = base58Decode(publicKeyBase58)
    if len(publicKeyBytes) != 32:
        return false
    
    signatureBytes = base58Decode(signatureBase58)
    if len(signatureBytes) != 64:
        return false
    
    messageBytes = utf8Encode(messageString)
    
    return ed25519Verify(publicKeyBytes, messageBytes, signatureBytes)
```

### Nonce Generation

Nonces must be cryptographically random and globally unique within their validity period. The recommended approach:

1. Generate 32 random bytes from a cryptographically secure random number generator
2. Encode as hexadecimal or base58
3. Store with the current timestamp

Pseudocode:
```
function generateNonce():
    randomBytes = cryptoRandomBytes(32)
    nonce = hexEncode(randomBytes)
    timestamp = currentTime()
    
    store(nonce, {
        created: timestamp,
        expires: timestamp + 15 minutes,
        used: false,
        publicKey: <associated-public-key>
    })
    
    return nonce
```

### Nonce Expiration Strategy

Nonces have a limited validity period to bound the window of vulnerability. The recommended expiration is 10-15 minutes, balancing security and user experience.

**Expiration checking**:
- Check expiration before verification
- Reject expired nonces even if otherwise valid
- Clean up expired nonces periodically to prevent storage growth

**Clock skew tolerance**: Servers should tolerate small clock skew (30-60 seconds) between client and server timestamps to account for time synchronization issues. However, this should be applied conservatively to avoid weakening the expiration mechanism.

### Domain Binding Implementation

The domain must be included in the signed message to prevent cross-domain signature reuse. Implementations must:

1. **Extract domain from request**: Use the `Host` header or configured domain
2. **Normalize domain**: Convert to lowercase, remove protocol and path
3. **Include in message**: Place domain in the specified location in the message format
4. **Verify on signature check**: Ensure the domain in the signed message matches the server's domain

Example domain normalization:
```
https://API.EXAMPLE.COM/some/path → api.example.com
```

### Security Parameters

**Minimum nonce entropy**: 128 bits (16 bytes, encoded as 32+ hex characters)

**Nonce validity period**: 10-15 minutes recommended, maximum 30 minutes

**Session duration**: Application-specific, typical range 1-24 hours

**Signature algorithm**: Ed25519 only, no fallback to weaker algorithms

**Encoding**: Base58 for public keys and signatures, UTF-8 for messages

---

## Session Management

This section describes session management strategies for SolAuth-authenticated users.

### Session Types

SolAuth supports two primary session management approaches, each with different trade-offs.

#### Stateful Sessions

In stateful session management, the server maintains session state in a database or cache.

**Mechanism**:
1. After successful authentication, generate a random session ID (minimum 128 bits)
2. Store session data in a backend store (database, Redis, etc.)
3. Return session ID to client as an opaque token
4. On each request, look up session data by ID

**Storage structure**:
```json
{
  "sessionId": "a1b2c3d4e5f6...",
  "publicKey": "7j8sKQN7ZHCxrz3YMwjXJ4mKqPvCt9xvR2hF5nE8pLmN",
  "createdAt": "2025-01-03T10:30:15Z",
  "expiresAt": "2025-01-03T11:30:15Z",
  "lastActivity": "2025-01-03T10:45:22Z",
  "ipAddress": "203.0.113.42",
  "userAgent": "Mozilla/5.0..."
}
```

**Advantages**:
- Immediate revocation capability
- Can update session data without reissuing token
- Can track detailed session metadata
- Can implement complex session policies (concurrent session limits, device tracking)

**Disadvantages**:
- Requires session storage infrastructure
- Lookups add latency to each request
- Requires distributed session store for multi-server deployments
- Storage costs grow with active user base

**Recommended for**:
- Applications requiring immediate logout/revocation
- Applications with complex session policies
- Monolithic deployments with centralized state

#### Stateless Sessions (JWT)

In stateless session management, all session data is encoded in a cryptographically signed token (JWT).

**Mechanism**:
1. After successful authentication, create a JWT containing claims
2. Sign JWT with server's secret key
3. Return JWT to client
4. On each request, verify JWT signature and extract claims

**JWT structure**:
```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "7j8sKQN7ZHCxrz3YMwjXJ4mKqPvCt9xvR2hF5nE8pLmN",
    "iss": "api.example.com",
    "iat": 1735902615,
    "exp": 1735906215,
    "jti": "a1b2c3d4e5f6..."
  }
}
```

**JWT claims**:
- `sub` (subject): The authenticated public key
- `iss` (issuer): The domain that issued the token
- `iat` (issued at): Unix timestamp when the token was created
- `exp` (expiration): Unix timestamp when the token expires
- `jti` (JWT ID): Unique identifier for this token (prevents reuse if revocation is implemented)

**Advantages**:
- No server-side session storage required
- Scales horizontally without shared state
- Works well with serverless and edge deployments
- Lower latency (no database lookup)

**Disadvantages**:
- Cannot immediately revoke tokens (must wait for expiration)
- Cannot update token data without reissue
- Token size larger than opaque session ID
- Requires careful key management for JWT signing

**Recommended for**:
- Serverless or edge deployments
- High-scale applications prioritizing performance
- Applications where immediate revocation is not critical

### Session Expiration

All sessions must have an expiration time. The expiration balances security and user experience.

**Recommended durations**:
- Short-lived sessions: 15-60 minutes (high security applications)
- Standard sessions: 1-4 hours (typical web applications)
- Long-lived sessions: 8-24 hours (user convenience priority)
- Persistent sessions: 7-30 days (with strict renewal policies)

**Absolute vs sliding expiration**:

**Absolute expiration**: Session expires at a fixed time regardless of activity
- Simpler to implement
- More predictable behavior
- Better for compliance requirements

**Sliding expiration**: Session expiration extends with each activity
- Better user experience (active users stay logged in)
- More complex to implement, especially with stateless sessions
- Risk of indefinite sessions if not bounded

**Hybrid approach**: Use sliding expiration up to a maximum absolute lifetime.

### Session Revocation

Session revocation terminates an authenticated session before its natural expiration.

#### Revocation in Stateful Sessions

Stateful sessions support immediate revocation:

1. Client sends revocation request with session ID
2. Server deletes session from storage
3. Subsequent requests with that session ID are rejected

**Revocation reasons**:
- User logout
- Security incident detected
- Administrator action
- Device lost/stolen
- Concurrent session limit exceeded

#### Revocation in Stateless Sessions (JWT)

Stateless sessions (JWT) do not support immediate revocation by design. Workarounds include:

**Short expiration with refresh tokens**:
- Issue short-lived access tokens (5-15 minutes)
- Issue longer-lived refresh tokens
- Client refreshes access token using refresh token
- Refresh tokens are stored server-side and can be revoked

**Revocation list**:
- Maintain a list of revoked JWT IDs (`jti` claim)
- Check each JWT against revocation list
- Defeats the stateless benefit but provides revocation

**Versioning**:
- Include a version number in the JWT
- Increment version on revocation
- Store current version per user in a cache
- Reject tokens with old versions

The refresh token approach is recommended as it balances statelessness with revocation capability.

### Session Security

#### Token Storage

**Web applications (cookies)**:
- Use HttpOnly cookies to prevent XSS access
- Use Secure flag to ensure HTTPS-only transmission
- Use SameSite=Strict or SameSite=Lax to prevent CSRF
- Set appropriate Domain and Path restrictions

Example cookie configuration:
```
Set-Cookie: solauth_token=<token>; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600
```

**Single-page applications (local storage)**:
- Store tokens in memory when possible (most secure)
- If persistence is needed, use localStorage or sessionStorage
- Be aware of XSS risks (any JavaScript can access localStorage)
- Consider using Web Workers for isolated token storage

**Mobile applications**:
- Use platform-specific secure storage (Keychain on iOS, KeyStore on Android)
- Never store tokens in plain text files
- Implement biometric protection for sensitive applications

#### Token Binding

Binding sessions to additional factors increases security:

**IP address binding**:
- Store IP address when session is created
- Reject requests from different IP addresses
- Problem: Users behind NAT or VPNs may have changing IPs
- Recommendation: Log IP changes but only enforce for high-security operations

**User agent binding**:
- Store User-Agent header when session is created
- Reject requests with different User-Agent
- Problem: User-Agent can be easily spoofed
- Recommendation: Use as signal for anomaly detection, not hard enforcement

**Device fingerprinting**:
- Generate a fingerprint from browser/device characteristics
- Compare fingerprint on each request
- More robust than User-Agent alone
- Privacy considerations: Avoid tracking across sites

### Concurrent Session Management

Applications may want to limit the number of concurrent sessions per user.

**Strategies**:

**Single session**: Only one active session per public key
- New authentication invalidates previous session
- Simplest to implement
- Poor experience if user has multiple devices

**Limited sessions**: Fixed number of concurrent sessions (e.g., 3-5)
- New authentication invalidates oldest session if limit reached
- Reasonable balance for most applications
- Track sessions per public key in database

**Unlimited sessions**: Allow any number of concurrent sessions
- Best user experience
- Requires revocation mechanism for user to manage sessions
- Higher risk if credentials are compromised

### Session Renewal

For long-running applications, session renewal allows extending an authenticated session without full re-authentication.

**Renewal strategies**:

**Explicit renewal**:
- Client calls a renewal endpoint with current valid token
- Server issues a new token with extended expiration
- Allows user verification (are you still there?) before renewal

**Automatic renewal**:
- Server automatically extends expiration on activity
- Transparent to user
- Risk of indefinite sessions if not bounded

**Refresh tokens**:
- Short-lived access tokens, long-lived refresh tokens
- Client uses refresh token to obtain new access token
- Refresh tokens can be revoked without affecting active access tokens

---

## Comparison with Other Authentication Systems

This section compares SolAuth with other authentication approaches commonly used in web applications.

| Feature | SolAuth | OAuth 2.0 | Username/Password | SIWE (Ethereum) |
|---------|---------|-----------|-------------------|-----------------|
| **Identity Anchor** | Solana wallet keypair | Third-party provider | Server-stored credential | Ethereum wallet keypair |
| **User Registration** | Not required | Provider account required | Required per service | Not required |
| **Credential Storage** | Client-side (wallet) | Provider-side | Server-side database | Client-side (wallet) |
| **Phishing Vulnerability** | Moderate (domain-dependent) | Low (provider-managed) | High (password reuse) | Moderate (domain-dependent) |
| **Credential Reuse Risk** | None (signatures are unique) | None (delegated) | High (common across services) | None (signatures are unique) |
| **Server Trust Requirements** | Minimal (stateless verification) | Provider trust required | High (password handling) | Minimal (stateless verification) |
| **Private Key Exposure** | Never transmitted | N/A | Password transmitted (hopefully over TLS) | Never transmitted |
| **Revocation Capability** | Session-based | Provider-managed | Immediate | Session-based |
| **Offline Authentication** | No (requires signature) | No (requires provider) | Possible (with local password hash) | No (requires signature) |
| **Multi-Device Support** | Depends on wallet export | Native | Native | Depends on wallet export |
| **Recovery Mechanism** | Seed phrase (user responsibility) | Provider-managed | Email/phone reset | Seed phrase (user responsibility) |
| **Cross-Platform Compatibility** | Solana ecosystem | Universal | Universal | Ethereum ecosystem |
| **Implementation Complexity** | Moderate | Moderate to High | Low | Moderate |
| **On-Chain Integration** | Native | None | None | Native |
| **Compliance Suitability** | Depends on jurisdiction | High (provider KYC) | Moderate | Depends on jurisdiction |
| **Cryptographic Strength** | Ed25519 (128-bit security) | Varies by provider | Varies (bcrypt, Argon2) | ECDSA secp256k1 |
| **Session Management** | Application-controlled | Application-controlled | Application-controlled | Application-controlled |
| **User Privacy** | High (no third party) | Low (provider tracking) | Moderate (service-specific) | High (no third party) |

### Detailed Comparisons

#### SolAuth vs OAuth 2.0

**Similarities**:
- Both delegate cryptographic proof (SolAuth to wallet, OAuth to provider)
- Both support session-based access after initial authentication
- Both require user consent for authentication

**Differences**:

**Trust model**: OAuth requires trust in the identity provider (Google, GitHub, etc.). The application must trust the provider to correctly authenticate users and to remain available. SolAuth requires no third-party trust; verification is purely cryptographic.

**Ecosystem lock-in**: OAuth ties user identity to the provider's ecosystem. If Google bans a user's account, they lose access to all services using Google OAuth. SolAuth identity is self-sovereign; no provider can revoke it.

**Privacy**: OAuth providers can track which services users authenticate to and when. SolAuth has no centralized tracking; authentication is direct between user and service.

**Complexity**: OAuth requires complex flows (authorization codes, token exchange, refresh tokens) and provider API integration. SolAuth is a simpler challenge-response protocol.

**Regulatory compliance**: OAuth providers often provide KYC, identity verification, and compliance features that applications may need for regulatory reasons. SolAuth provides no identity verification beyond wallet control.

**When to use OAuth**: Use OAuth when integrating with existing user bases, when regulatory compliance requires identity verification, or when users expect to use familiar accounts (Google, GitHub).

**When to use SolAuth**: Use SolAuth for blockchain-native applications, when user privacy is a priority, when self-sovereign identity is desired, or when OAuth providers are not appropriate for the use case.

#### SolAuth vs Username/Password

**Similarities**:
- Both require user action to authenticate
- Both support session-based access after authentication
- Both are service-specific (no cross-service single sign-on)

**Differences**:

**Credential storage**: Passwords must be stored (hashed) server-side, creating a high-value target for attackers. SolAuth requires no server-side credential storage.

**Credential transmission**: Passwords are transmitted to the server (hopefully over TLS), creating a brief window where the server sees the plaintext password. Private keys never leave the wallet in SolAuth.

**Credential reuse**: Users often reuse passwords across services, so a breach at one service compromises accounts at other services. Wallet signatures are cryptographically bound to the specific authentication attempt and cannot be reused.

**Cryptographic proof**: Password authentication proves knowledge of a shared secret. SolAuth proves possession of a private key through a signature.

**Account recovery**: Password systems can implement email/phone-based recovery. Wallet recovery depends on the user's seed phrase backup, which is entirely the user's responsibility.

**Implementation complexity**: Password authentication is simpler to implement initially but requires secure hashing (bcrypt, Argon2), salt management, and secure password reset flows. SolAuth requires signature verification but no password storage or reset mechanisms.

**When to use passwords**: Use passwords for applications requiring username-based identity, when wallet integration is not feasible, or when users do not have cryptocurrency wallets.

**When to use SolAuth**: Use SolAuth for blockchain-native applications, when eliminating password databases is desired, or when users are expected to have Solana wallets.

#### SolAuth vs SIWE (Sign-In with Ethereum)

**Similarities**:
- Both use wallet signatures for authentication
- Both are challenge-response protocols
- Both provide self-sovereign identity
- Both include domain binding
- Both follow similar security principles

**Differences**:

**Blockchain ecosystem**: SIWE is for Ethereum, SolAuth is for Solana.

**Signature algorithm**: SIWE uses ECDSA secp256k1, SolAuth uses Ed25519.

**Message format**: SIWE has a more structured message format defined in EIP-4361. SolAuth uses a simpler format.

**Standardization**: SIWE is an Ethereum Improvement Proposal (EIP-4361) with community consensus. SolAuth is a protocol specification without formal governance.

**Wallet ecosystem**: SIWE integrates with Ethereum wallets (MetaMask, etc.). SolAuth integrates with Solana wallets (Phantom, Solflare, etc.).

**When to use SIWE**: Use SIWE for Ethereum-native applications or when users primarily hold Ethereum wallets.

**When to use SolAuth**: Use SolAuth for Solana-native applications or when users primarily hold Solana wallets.

---

## Usage Examples

This section provides concrete examples of implementing SolAuth in different contexts.

### Web Application (React + Node.js)

#### Client-Side (React)

```javascript
import { useWallet } from '@solana/wallet-adapter-react';
import { useState } from 'react';

function AuthComponent() {
  const { publicKey, signMessage } = useWallet();
  const [session, setSession] = useState(null);

  async function authenticate() {
    if (!publicKey || !signMessage) {
      throw new Error('Wallet not connected');
    }

    // Step 1: Request challenge from server
    const challengeResponse = await fetch('https://api.example.com/auth/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        publicKey: publicKey.toBase58()
      })
    });

    const { challenge } = await challengeResponse.json();

    // Step 2: Sign the challenge message
    const messageBytes = new TextEncoder().encode(challenge.message);
    const signature = await signMessage(messageBytes);

    // Step 3: Submit signature for verification
    const verifyResponse = await fetch('https://api.example.com/auth/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        publicKey: publicKey.toBase58(),
        nonce: challenge.nonce,
        signature: Buffer.from(signature).toString('base64'),
        message: challenge.message
      })
    });

    const { session: newSession } = await verifyResponse.json();
    setSession(newSession);

    // Store session token for subsequent requests
    localStorage.setItem('solauth_token', newSession.token);
  }

  async function makeAuthenticatedRequest() {
    const token = localStorage.getItem('solauth_token');
    
    const response = await fetch('https://api.example.com/protected/resource', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    return response.json();
  }

  async function logout() {
    const token = localStorage.getItem('solauth_token');
    
    await fetch('https://api.example.com/auth/revoke', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    localStorage.removeItem('solauth_token');
    setSession(null);
  }

  return (
    <div>
      {!session ? (
        <button onClick={authenticate}>
          Sign In with Wallet
        </button>
      ) : (
        <div>
          <p>Authenticated as: {session.publicKey}</p>
          <button onClick={logout}>Sign Out</button>
        </div>
      )}
    </div>
  );
}
```

#### Server-Side (Node.js + Express)

```javascript
const express = require('express');
const nacl = require('tweetnacl');
const bs58 = require('bs58');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// In-memory nonce store (use Redis in production)
const nonceStore = new Map();

// In-memory session store (use database in production)
const sessionStore = new Map();

const SERVER_DOMAIN = 'api.example.com';
const NONCE_EXPIRY_MS = 15 * 60 * 1000; // 15 minutes
const SESSION_EXPIRY_MS = 60 * 60 * 1000; // 1 hour

// Helper function to generate nonce
function generateNonce() {
  return crypto.randomBytes(32).toString('hex');
}

// Helper function to construct message
function constructMessage(domain, nonce, issuedAt, expiresAt) {
  return `SolAuth Authentication Request

Domain: ${domain}
Nonce: ${nonce}
Issued At: ${issuedAt}
Expires At: ${expiresAt}

By signing this message, you are authenticating to ${domain}.`;
}

// Challenge endpoint
app.post('/auth/challenge', (req, res) => {
  const { publicKey } = req.body;

  if (!publicKey) {
    return res.status(400).json({ error: 'Public key required' });
  }

  // Validate public key format
  try {
    const decoded = bs58.decode(publicKey);
    if (decoded.length !== 32) {
      return res.status(400).json({ error: 'Invalid public key length' });
    }
  } catch (err) {
    return res.status(400).json({ error: 'Invalid public key format' });
  }

  const nonce = generateNonce();
  const issuedAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + NONCE_EXPIRY_MS).toISOString();
  const message = constructMessage(SERVER_DOMAIN, nonce, issuedAt, expiresAt);

  // Store nonce
  nonceStore.set(nonce, {
    publicKey,
    issuedAt: Date.now(),
    expiresAt: Date.now() + NONCE_EXPIRY_MS,
    used: false
  });

  res.json({
    challenge: {
      nonce,
      domain: SERVER_DOMAIN,
      issuedAt,
      expiresAt,
      message
    }
  });
});

// Verify endpoint
app.post('/auth/verify', (req, res) => {
  const { publicKey, nonce, signature, message } = req.body;

  // Validate required fields
  if (!publicKey || !nonce || !signature || !message) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  // Check nonce exists
  const nonceData = nonceStore.get(nonce);
  if (!nonceData) {
    return res.status(401).json({ error: 'NONCE_NOT_FOUND' });
  }

  // Check nonce not expired
  if (Date.now() > nonceData.expiresAt) {
    nonceStore.delete(nonce);
    return res.status(401).json({ error: 'NONCE_EXPIRED' });
  }

  // Check nonce not used
  if (nonceData.used) {
    return res.status(401).json({ error: 'NONCE_ALREADY_USED' });
  }

  // Check public key matches
  if (nonceData.publicKey !== publicKey) {
    return res.status(401).json({ error: 'PUBLIC_KEY_MISMATCH' });
  }

  // Reconstruct expected message
  const issuedAt = new Date(nonceData.issuedAt).toISOString();
  const expiresAt = new Date(nonceData.expiresAt).toISOString();
  const expectedMessage = constructMessage(SERVER_DOMAIN, nonce, issuedAt, expiresAt);

  // Verify message matches
  if (message !== expectedMessage) {
    return res.status(401).json({ error: 'MESSAGE_MISMATCH' });
  }

  // Verify signature
  try {
    const publicKeyBytes = bs58.decode(publicKey);
    const signatureBytes = Buffer.from(signature, 'base64');
    const messageBytes = Buffer.from(message, 'utf8');

    const isValid = nacl.sign.detached.verify(
      messageBytes,
      signatureBytes,
      publicKeyBytes
    );

    if (!isValid) {
      return res.status(401).json({ error: 'INVALID_SIGNATURE' });
    }
  } catch (err) {
    return res.status(401).json({ error: 'SIGNATURE_VERIFICATION_FAILED' });
  }

  // Mark nonce as used
  nonceData.used = true;
  nonceStore.set(nonce, nonceData);

  // Create session
  const sessionId = crypto.randomBytes(32).toString('hex');
  const sessionIssuedAt = new Date().toISOString();
  const sessionExpiresAt = new Date(Date.now() + SESSION_EXPIRY_MS).toISOString();

  sessionStore.set(sessionId, {
    publicKey,
    issuedAt: Date.now(),
    expiresAt: Date.now() + SESSION_EXPIRY_MS,
    lastActivity: Date.now()
  });

  res.json({
    session: {
      token: sessionId,
      publicKey,
      issuedAt: sessionIssuedAt,
      expiresAt: sessionExpiresAt
    }
  });
});

// Session validation middleware
function authenticateSession(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No session token provided' });
  }

  const token = authHeader.substring(7);
  const session = sessionStore.get(token);

  if (!session) {
    return res.status(401).json({ error: 'Invalid session token' });
  }

  if (Date.now() > session.expiresAt) {
    sessionStore.delete(token);
    return res.status(403).json({ error: 'Session expired' });
  }

  // Update last activity
  session.lastActivity = Date.now();
  sessionStore.set(token, session);

  // Attach session data to request
  req.session = session;
  req.sessionToken = token;

  next();
}

// Get session endpoint
app.get('/auth/session', authenticateSession, (req, res) => {
  res.json({
    session: {
      publicKey: req.session.publicKey,
      issuedAt: new Date(req.session.issuedAt).toISOString(),
      expiresAt: new Date(req.session.expiresAt).toISOString(),
      lastActivity: new Date(req.session.lastActivity).toISOString()
    }
  });
});

// Revoke session endpoint
app.post('/auth/revoke', authenticateSession, (req, res) => {
  sessionStore.delete(req.sessionToken);
  
  res.json({
    revoked: true,
    publicKey: req.session.publicKey
  });
});

// Example protected endpoint
app.get('/protected/resource', authenticateSession, (req, res) => {
  res.json({
    message: 'This is a protected resource',
    authenticatedAs: req.session.publicKey
  });
});

app.listen(3000, () => {
  console.log('SolAuth server running on port 3000');
});
```

### API Backend (Python + Flask)

```python
from flask import Flask, request, jsonify
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
import base58
import secrets
import time
from datetime import datetime, timedelta

app = Flask(__name__)

# In-memory stores (use Redis/database in production)
nonce_store = {}
session_store = {}

SERVER_DOMAIN = 'api.example.com'
NONCE_EXPIRY_SECONDS = 900  # 15 minutes
SESSION_EXPIRY_SECONDS = 3600  # 1 hour

def generate_nonce():
    return secrets.token_hex(32)

def construct_message(domain, nonce, issued_at, expires_at):
    return f"""SolAuth Authentication Request

Domain: {domain}
Nonce: {nonce}
Issued At: {issued_at}
Expires At: {expires_at}

By signing this message, you are authenticating to {domain}."""

@app.route('/auth/challenge', methods=['POST'])
def challenge():
    data = request.json
    public_key = data.get('publicKey')
    
    if not public_key:
        return jsonify({'error': 'Public key required'}), 400
    
    # Validate public key format
    try:
        decoded = base58.b58decode(public_key)
        if len(decoded) != 32:
            return jsonify({'error': 'Invalid public key length'}), 400
    except Exception:
        return jsonify({'error': 'Invalid public key format'}), 400
    
    nonce = generate_nonce()
    issued_at = datetime.utcnow()
    expires_at = issued_at + timedelta(seconds=NONCE_EXPIRY_SECONDS)
    
    issued_at_iso = issued_at.strftime('%Y-%m-%dT%H:%M:%SZ')
    expires_at_iso = expires_at.strftime('%Y-%m-%dT%H:%M:%SZ')
    
    message = construct_message(SERVER_DOMAIN, nonce, issued_at_iso, expires_at_iso)
    
    nonce_store[nonce] = {
        'publicKey': public_key,
        'issuedAt': time.time(),
        'expiresAt': time.time() + NONCE_EXPIRY_SECONDS,
        'used': False,
        'message': message
    }
    
    return jsonify({
        'challenge': {
            'nonce': nonce,
            'domain': SERVER_DOMAIN,
            'issuedAt': issued_at_iso,
            'expiresAt': expires_at_iso,
            'message': message
        }
    })

@app.route('/auth/verify', methods=['POST'])
def verify():
    data = request.json
    public_key = data.get('publicKey')
    nonce = data.get('nonce')
    signature = data.get('signature')
    message = data.get('message')
    
    if not all([public_key, nonce, signature, message]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Check nonce exists
    nonce_data = nonce_store.get(nonce)
    if not nonce_data:
        return jsonify({'error': 'NONCE_NOT_FOUND'}), 401
    
    # Check nonce not expired
    if time.time() > nonce_data['expiresAt']:
        del nonce_store[nonce]
        return jsonify({'error': 'NONCE_EXPIRED'}), 401
    
    # Check nonce not used
    if nonce_data['used']:
        return jsonify({'error': 'NONCE_ALREADY_USED'}), 401
    
    # Check public key matches
    if nonce_data['publicKey'] != public_key:
        return jsonify({'error': 'PUBLIC_KEY_MISMATCH'}), 401
    
    # Verify message matches
    if message != nonce_data['message']:
        return jsonify({'error': 'MESSAGE_MISMATCH'}), 401
    
    # Verify signature
    try:
        public_key_bytes = base58.b58decode(public_key)
        signature_bytes = base64.b64decode(signature)
        message_bytes = message.encode('utf-8')
        
        verify_key = VerifyKey(public_key_bytes)
        verify_key.verify(message_bytes, signature_bytes)
    except BadSignatureError:
        return jsonify({'error': 'INVALID_SIGNATURE'}), 401
    except Exception as e:
        return jsonify({'error': 'SIGNATURE_VERIFICATION_FAILED'}), 401
    
    # Mark nonce as used
    nonce_data['used'] = True
    nonce_store[nonce] = nonce_data
    
    # Create session
    session_id = secrets.token_hex(32)
    session_issued_at = datetime.utcnow()
    session_expires_at = session_issued_at + timedelta(seconds=SESSION_EXPIRY_SECONDS)
    
    session_store[session_id] = {
        'publicKey': public_key,
        'issuedAt': time.time(),
        'expiresAt': time.time() + SESSION_EXPIRY_SECONDS,
        'lastActivity': time.time()
    }
    
    return jsonify({
        'session': {
            'token': session_id,
            'publicKey': public_key,
            'issuedAt': session_issued_at.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'expiresAt': session_expires_at.strftime('%Y-%m-%dT%H:%M:%SZ')
        }
    })

def authenticate_session(f):
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'No session token provided'}), 401
        
        token = auth_header[7:]
        session = session_store.get(token)
        
        if not session:
            return jsonify({'error': 'Invalid session token'}), 401
        
        if time.time() > session['expiresAt']:
            del session_store[token]
            return jsonify({'error': 'Session expired'}), 403
        
        # Update last activity
        session['lastActivity'] = time.time()
        session_store[token] = session
        
        # Pass session to route
        request.session = session
        request.session_token = token
        
        return f(*args, **kwargs)
    
    wrapper.__name__ = f.__name__
    return wrapper

@app.route('/auth/session', methods=['GET'])
@authenticate_session
def get_session():
    return jsonify({
        'session': {
            'publicKey': request.session['publicKey'],
            'issuedAt': datetime.fromtimestamp(request.session['issuedAt']).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'expiresAt': datetime.fromtimestamp(request.session['expiresAt']).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'lastActivity': datetime.fromtimestamp(request.session['lastActivity']).strftime('%Y-%m-%dT%H:%M:%SZ')
        }
    })

@app.route('/auth/revoke', methods=['POST'])
@authenticate_session
def revoke():
    public_key = request.session['publicKey']
    del session_store[request.session_token]
    
    return jsonify({
        'revoked': True,
        'publicKey': public_key
    })

if __name__ == '__main__':
    app.run(port=3000)
```

### CLI Tool (Python)

```python
#!/usr/bin/env python3
import requests
import base58
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder
import json
import sys

API_BASE = 'https://api.example.com'
TOKEN_FILE = '.solauth_token'

def load_keypair(keyfile_path):
    """Load keypair from file (Solana keypair JSON format)"""
    with open(keyfile_path, 'r') as f:
        keypair_data = json.load(f)
    
    secret_key_bytes = bytes(keypair_data[:32])
    signing_key = SigningKey(secret_key_bytes)
    
    return signing_key

def authenticate(keyfile_path):
    """Authenticate with the server using wallet signature"""
    print('Loading keypair...')
    signing_key = load_keypair(keyfile_path)
    public_key = signing_key.verify_key
    public_key_b58 = base58.b58encode(bytes(public_key)).decode('utf-8')
    
    print(f'Public key: {public_key_b58}')
    print('Requesting challenge from server...')
    
    # Request challenge
    challenge_response = requests.post(
        f'{API_BASE}/auth/challenge',
        json={'publicKey': public_key_b58}
    )
    
    if challenge_response.status_code != 200:
        print(f'Error requesting challenge: {challenge_response.text}')
        sys.exit(1)
    
    challenge_data = challenge_response.json()['challenge']
    message = challenge_data['message']
    nonce = challenge_data['nonce']
    
    print('Challenge received. Signing message...')
    print(f'\nMessage to sign:\n{message}\n')
    
    # Sign message
    message_bytes = message.encode('utf-8')
    signature = signing_key.sign(message_bytes, encoder=RawEncoder)
    signature_b64 = base64.b64encode(signature.signature).decode('utf-8')
    
    print('Submitting signature for verification...')
    
    # Verify signature
    verify_response = requests.post(
        f'{API_BASE}/auth/verify',
        json={
            'publicKey': public_key_b58,
            'nonce': nonce,
            'signature': signature_b64,
            'message': message
        }
    )
    
    if verify_response.status_code != 200:
        print(f'Authentication failed: {verify_response.text}')
        sys.exit(1)
    
    session_data = verify_response.json()['session']
    token = session_data['token']
    
    # Save token
    with open(TOKEN_FILE, 'w') as f:
        f.write(token)
    
    print(f'Authentication successful!')
    print(f'Session expires at: {session_data["expiresAt"]}')
    print(f'Token saved to {TOKEN_FILE}')

def make_authenticated_request(endpoint):
    """Make an authenticated request to the API"""
    try:
        with open(TOKEN_FILE, 'r') as f:
            token = f.read().strip()
    except FileNotFoundError:
        print('Not authenticated. Run: solauth-cli login <keyfile>')
        sys.exit(1)
    
    response = requests.get(
        f'{API_BASE}{endpoint}',
        headers={'Authorization': f'Bearer {token}'}
    )
    
    if response.status_code == 401:
        print('Session expired. Please authenticate again.')
        sys.exit(1)
    
    return response.json()

def logout():
    """Revoke current session"""
    try:
        with open(TOKEN_FILE, 'r') as f:
            token = f.read().strip()
    except FileNotFoundError:
        print('Not authenticated.')
        return
    
    requests.post(
        f'{API_BASE}/auth/revoke',
        headers={'Authorization': f'Bearer {token}'}
    )
    
    import os
    os.remove(TOKEN_FILE)
    print('Logged out successfully')

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage:')
        print('  solauth-cli login <keyfile>')
        print('  solauth-cli get <endpoint>')
        print('  solauth-cli logout')
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'login':
        if len(sys.argv) < 3:
            print('Usage: solauth-cli login <keyfile>')
            sys.exit(1)
        authenticate(sys.argv[2])
    elif command == 'get':
        if len(sys.argv) < 3:
            print('Usage: solauth-cli get <endpoint>')
            sys.exit(1)
        result = make_authenticated_request(sys.argv[2])
        print(json.dumps(result, indent=2))
    elif command == 'logout':
        logout()
    else:
        print(f'Unknown command: {command}')
        sys.exit(1)
```

---

## Security Considerations

This section provides explicit security guidance for implementing and deploying SolAuth.

### Transport Security

**Requirement**: All SolAuth endpoints must be served over TLS (HTTPS). This is non-negotiable.

**Rationale**: While the signature itself is tamper-evident, several attack vectors exist without TLS:
- Session tokens can be intercepted and stolen
- Challenge requests can be observed to fingerprint users
- Man-in-the-middle attacks can inject malicious JavaScript
- Downgrade attacks can force cleartext communication

**Implementation**: Configure TLS 1.2 or TLS 1.3 with strong cipher suites. Disable SSLv3, TLS 1.0, and TLS 1.1. Use HTTP Strict Transport Security (HSTS) headers to prevent downgrade attacks.

### Nonce Security

**Randomness requirement**: Nonces must be generated using a cryptographically secure random number generator (CSPRNG). Predictable nonces undermine the entire authentication mechanism.

**Acceptable sources**:
- `/dev/urandom` (Unix/Linux)
- `crypto.randomBytes()` (Node.js)
- `secrets.token_hex()` (Python)
- `crypto/rand` (Go)

**Unacceptable sources**:
- `Math.random()` (JavaScript)
- `/dev/random` (blocking, unnecessary)
- Time-based seeds
- Incrementing counters

**Storage requirement**: Nonces must be stored in a way that persists across server restarts for the duration of their validity period. In distributed deployments, nonce storage must be shared across all server instances. Redis, Memcached, or a dedicated nonce table in the database are suitable options.

**Cleanup**: Expired nonces should be periodically removed from storage to prevent unbounded growth. A background job that runs every 5-15 minutes is sufficient.

### Signature Verification

**Critical checks** (in order):
1. Nonce exists and has not expired
2. Nonce has not been previously used
3. Public key matches the one associated with the nonce
4. Message content matches expected format and values
5. Cryptographic signature is valid

**Common implementation errors**:

**Error**: Skipping nonce expiration check
**Impact**: Allows indefinite reuse of captured signatures
**Fix**: Always check current time against nonce expiration timestamp

**Error**: Not marking nonces as used after verification
**Impact**: Allows signature replay within validity window
**Fix**: Mark nonce as used in storage immediately after successful verification, before session creation

**Error**: Using string comparison for message verification
**Impact**: Whitespace differences, encoding issues cause false positives/negatives
**Fix**: Normalize messages before comparison, or better yet, reconstruct expected message from stored parameters

**Error**: Verifying signature before checking nonce validity
**Impact**: Expensive cryptographic operations performed on invalid/expired nonces
**Fix**: Check nonce validity first (fast database lookup), then verify signature (expensive crypto operation)

### Message Format Consistency

The message format must be exactly consistent between challenge generation and signature verification. Any deviation will cause verification to fail.

**Common pitfalls**:
- Line ending differences (LF vs CRLF)
- Trailing whitespace
- Timestamp format variations (millisecond precision, timezone handling)
- Domain capitalization
- String encoding (UTF-8 vs other encodings)

**Best practice**: Store the complete message string when generating the nonce. During verification, compare the submitted message against this stored message. This eliminates reconstruction errors.

### Session Token Security

**Token entropy**: Session tokens must have sufficient entropy to prevent brute-force guessing. Minimum 128 bits (16 bytes) is recommended, typically encoded as 32 hexadecimal characters or equivalent base64.

**Token storage**:

**Server-side** (stateful sessions):
- Store in database with appropriate indexing
- Include expiration timestamp
- Include creation timestamp
- Consider including IP address for anomaly detection

**Client-side**:
- Use HttpOnly cookies for web applications (prevents XSS access)
- Use Secure flag (HTTPS-only transmission)
- Use SameSite=Strict or SameSite=Lax (CSRF protection)
- For non-cookie storage, ensure secure storage mechanisms

**JWT considerations**:

If using JWTs for stateless sessions:
- Use a strong signing algorithm (HS256, RS256, ES256)
- Do not use "none" algorithm
- Validate signature on every request
- Validate expiration claim (exp)
- Validate issued-at claim (iat) to prevent clock skew attacks
- Validate issuer claim (iss) if multiple services share keys
- Use short expiration times (15-60 minutes) with refresh tokens

### Rate Limiting

Rate limiting is essential to prevent abuse and denial-of-service attacks.

**Challenge endpoint**:
- Limit: 10 requests per minute per IP address
- Purpose: Prevent nonce exhaustion attacks
- Implementation: Use sliding window or token bucket algorithm

**Verify endpoint**:
- Limit: 5 requests per minute per public key
- Purpose: Prevent brute-force signature attempts
- Implementation: Track attempts per public key, lock out after threshold

**Session endpoints**:
- Limit: 60 requests per minute per session
- Purpose: Prevent session abuse
- Implementation: Standard per-session rate limiting

**Global rate limits**:
- Consider global per-IP rate limits across all endpoints
- Consider global per-server rate limits to prevent resource exhaustion

### Time Synchronization

Authentication relies on timestamp comparison. Servers must have accurate time synchronization.

**Requirements**:
- Use NTP (Network Time Protocol) to synchronize server clocks
- Monitor clock drift and alert on significant deviation
- Consider clock skew tolerance (30-60 seconds) in expiration checks
- Log timestamp-related failures for monitoring

**Time-based attacks**:
- If server clock is far ahead, nonces appear expired immediately
- If server clock is far behind, expired nonces are accepted
- If client and server clocks differ significantly, legitimate users cannot authenticate

### Domain Binding Enforcement

The domain in the signed message must match the server's configured domain. This prevents signature reuse across different services.

**Implementation**:
- Configure the server's domain explicitly (do not auto-detect)
- Normalize domains to lowercase
- Strip protocol, port, and path from domains
- Compare signed domain against configured domain, reject mismatches

**Subdomain considerations**:
- Decide whether to bind to specific subdomain (api.example.com) or wildcard (*.example.com)
- More specific binding is more secure but less flexible
- Document the binding policy clearly for users

### Private Key Protection

SolAuth does not handle private keys, but implementers and users must understand key security.

**User responsibility**:
- Private keys must never be shared or transmitted
- Users should use hardware wallets for high-value accounts
- Seed phrases should be stored securely offline
- Users should understand the permanence of key compromise

**Application responsibility**:
- Never request or handle private keys directly
- Use wallet adapters that handle key management
- Do not log or store signatures longer than necessary
- Educate users about phishing and key security

### Input Validation

All inputs to SolAuth endpoints must be validated.

**Public key validation**:
- Verify base58 decoding succeeds
- Verify length is exactly 32 bytes
- Optional: Verify bytes represent a valid curve point

**Nonce validation**:
- Verify format matches expected format (hex, base58, etc.)
- Verify length is sufficient (minimum 32 characters)
- Do not allow SQL injection characters if storing in database

**Signature validation**:
- Verify base58/base64 decoding succeeds
- Verify length is exactly 64 bytes

**Message validation**:
- Verify message matches expected structure
- Verify timestamps are valid ISO 8601 format
- Verify domain matches expected format

### Error Handling

Error messages must be carefully designed to avoid information leakage while providing useful feedback.

**Acceptable error messages**:
- "Invalid signature" (does not reveal why)
- "Nonce expired" (reveals timing, acceptable)
- "Authentication failed" (generic, safe)

**Unacceptable error messages**:
- "Nonce valid but signature verification failed" (reveals internal state)
- "Public key XYZ does not exist in our database" (reveals enumeration)
- Stack traces or internal error details

**Logging**: Log detailed error information server-side for debugging, but return generic messages to clients.

### Monitoring and Alerting

Implement monitoring for security-relevant events:

**High-priority alerts**:
- Unusual number of failed authentication attempts
- Repeated nonce reuse attempts (possible replay attack)
- High rate of expired nonce usage (possible clock skew or attack)
- Session hijacking indicators (session used from multiple IPs)

**Metrics to track**:
- Authentication success/failure rates
- Average nonce lifetime before usage
- Session duration distribution
- Failed verification reasons breakdown

### Denial of Service Considerations

**Nonce storage exhaustion**: An attacker could request many challenges without completing authentication, exhausting nonce storage. Mitigate with:
- Rate limiting on challenge endpoint
- Aggressive nonce expiration (10-15 minutes)
- Maximum nonce count per IP address
- Regular cleanup of expired nonces

**Cryptographic operation exhaustion**: Signature verification is computationally expensive. Attackers could submit many invalid signatures to consume CPU. Mitigate with:
- Rate limiting on verify endpoint
- Validate nonce existence before cryptographic operations
- Reject obviously invalid signatures before verification
- Consider proof-of-work or CAPTCHA for repeated failures

**Session storage exhaustion**: Attackers could create many sessions. Mitigate with:
- Maximum sessions per public key
- Maximum total active sessions
- Aggressive session expiration for inactive sessions
- Session storage limits and oldest-first eviction

### Compliance and Legal Considerations

Depending on jurisdiction and application type, consider:

**Data protection**: Session data may include IP addresses and other personal information. Comply with GDPR, CCPA, and other data protection regulations. Provide mechanisms for users to view, export, and delete their session data.

**Authentication logs**: Log authentication events for security and compliance purposes. Retain logs according to legal requirements. Protect logs from unauthorized access.

**KYC/AML**: SolAuth provides only proof of wallet control, not identity verification. Applications subject to KYC/AML regulations must implement additional identity verification.

**Accessibility**: Ensure wallet interfaces clearly display authentication requests for users with accessibility needs.

### Testing

Security testing should include:

**Unit tests**:
- Signature verification with valid/invalid signatures
- Nonce expiration logic
- Message format validation
- Domain binding enforcement

**Integration tests**:
- Complete authentication flow
- Session lifecycle (create, use, expire, revoke)
- Error handling
- Rate limiting

**Security tests**:
- Replay attack attempts
- Signature reuse across domains
- Expired nonce usage
- Concurrent nonce usage
- Session hijacking scenarios

**Penetration testing**:
- Engage security professionals to test the implementation
- Test in an environment similar to production
- Address findings before production deployment

---

## Roadmap

This section outlines potential future developments for SolAuth. These are areas of active exploration and community feedback is welcome.

### SDK Development

**Objective**: Provide official SDKs in multiple languages to reduce implementation burden and ensure security best practices.

**Languages under consideration**:
- JavaScript/TypeScript (client and server)
- Python (server)
- Rust (server, performance-critical applications)
- Go (server, infrastructure applications)
- Java/Kotlin (Android, enterprise backends)
- Swift (iOS applications)

**SDK features**:
- Challenge generation and verification
- Session management utilities
- Wallet adapter integrations
- Middleware for popular frameworks (Express, Flask, FastAPI, etc.)
- Configuration validation
- Built-in rate limiting
- Comprehensive test suites

### Permission Scopes

**Objective**: Allow authenticated sessions to carry specific permission scopes, limiting what actions can be performed.

**Use case**: A user authenticates but only grants permission for read-only access, or access to specific program interactions.

**Approach**:
- Extend challenge message to include requested scopes
- User reviews and approves specific permissions during signature
- Server validates scope claims in session token
- Applications check required scopes before executing actions

**Challenges**:
- Defining standardized scope vocabulary
- Ensuring wallet interfaces clearly display permission requests
- Balancing granularity with user experience

### Session Delegation

**Objective**: Allow users to delegate session creation authority to another party without sharing private keys.

**Use case**: Service providers that manage multiple user accounts, sub-account systems, or automated trading systems.

**Approach**:
- Use Solana's native delegation primitives
- Cryptographically bind delegated sessions to delegator and delegatee
- Time-limited delegation with explicit expiration
- Revocable by the delegator at any time

**Security considerations**:
- Delegation must be explicit and user-initiated
- Delegatee capabilities must be clearly scoped
- Audit trail of delegated actions

### Multi-Signature Support

**Objective**: Support authentication requiring signatures from multiple wallets (M-of-N).

**Use case**: Organization accounts requiring multiple signers, high-security operations, joint custody.

**Approach**:
- Challenge includes multiple public keys and signature threshold
- Each signer independently signs the challenge
- Server collects signatures and verifies threshold is met
- Session is created only when threshold is satisfied

**Implementation challenges**:
- Coordinating multiple signatures in real-time
- Partial signature timeout handling
- User experience for multi-party authentication

### On-Chain Session Registry

**Objective**: Optionally record authenticated sessions on-chain for transparency and auditability.

**Use case**: DAO governance, regulatory compliance, audit requirements.

**Approach**:
- Create a Solana program for session registration
- Write session metadata to on-chain account
- Applications can verify session exists on-chain
- Public auditability of authentication events

**Trade-offs**:
- Transaction fees for session creation
- Public visibility of authentication events
- Slower session creation due to block confirmation
- Immutable record (cannot truly delete, only mark revoked)

### Enhanced Session Management

**Features under consideration**:
- Session transfer between devices (with explicit user approval)
- Session upgrade (increasing permission scope mid-session)
- Concurrent session limits with user control
- Session activity history and audit logs
- Geographic restrictions on session usage
- Device fingerprinting and anomaly detection

### Wallet Integration Improvements

**Objective**: Better integrate with wallet interfaces to improve user experience and security.

**Initiatives**:
- Standardized message formatting across wallets
- Rich permission display in wallet interfaces
- Warning indicators for suspicious domains
- One-click authentication flows
- Hardware wallet optimization
- Mobile wallet deep linking

### Interoperability

**Objective**: Enable SolAuth to work alongside other authentication mechanisms.

**Scenarios**:
- Fallback authentication (password if wallet unavailable)
- Combined authentication (password AND wallet signature)
- Federation with other blockchain authentication systems
- OAuth integration (wallet auth with OAuth scopes)

### Developer Tools

**Objective**: Provide tools to make SolAuth implementation easier and more secure.

**Tools under consideration**:
- CLI tool for testing authentication flows
- Mock wallet for development/testing
- Security scanner for SolAuth implementations
- Documentation generator for API endpoints
- Interactive API playground
- Implementation best practices guide

### Performance Optimization

**Objective**: Reduce latency and improve throughput of authentication operations.

**Optimizations under consideration**:
- Signature verification caching
- Nonce pre-generation and pooling
- Optimized storage backends (Redis, Cassandra)
- Edge deployment support
- WebAuthn integration for biometric binding

### Standardization

**Objective**: Establish SolAuth as a community standard with governance and versioning.

**Steps**:
- Formal specification document
- Reference implementation with test vectors
- Community working group
- Version management and migration paths
- Interoperability testing between implementations

---

## License

SolAuth is released under the MIT License.

Copyright (c) 2026 SolAuth Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## Contributing

SolAuth is an open-source project and welcomes contributions from the community. Contributions can take many forms:

- Bug reports and security vulnerability reports
- Feature requests and design proposals
- Code contributions (bug fixes, new features, optimizations)
- Documentation improvements
- SDK development
- Test coverage expansion
- Example applications and tutorials

**Security vulnerabilities**: If you discover a security vulnerability in SolAuth, please report it privately to the maintainers before public disclosure. This allows time to develop and deploy fixes before the vulnerability becomes public knowledge.

**Code contributions**: Follow the standard GitHub pull request workflow. Ensure code passes all tests and includes appropriate test coverage. Follow the existing code style and documentation conventions.

**Design proposals**: For significant changes to the protocol or architecture, open an issue for discussion before implementing. This ensures alignment with project goals and avoids wasted effort on changes that may not be accepted.

---

## Support and Community

**Documentation**: This README serves as the primary documentation. Additional documentation for specific implementations and SDKs will be maintained in their respective repositories.

**Issue tracking**: Use the GitHub issue tracker to report bugs, request features, or ask questions.

**Discussions**: For general questions, design discussions, or community interaction, use GitHub Discussions.

**Security contact**: For security-sensitive issues, contact the maintainers directly via email (to be provided).

---

## Acknowledgments

SolAuth builds upon prior work in wallet-based authentication, particularly:

- Sign-In with Ethereum (SIWE / EIP-4361)
- OAuth 2.0 specification and implementations
- Solana's Ed25519 signature scheme and wallet adapters
- The broader blockchain authentication ecosystem

We thank the developers, researchers, and community members who have contributed to these foundational technologies.

---

**Version**: 1.0.0  
**Last Updated**: 2026-01-03  
**Status**: Specification