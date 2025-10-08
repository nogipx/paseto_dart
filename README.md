# paseto_dart

Unofficial [PASETO](https://paseto.io) (Platform-Agnostic Security Tokens) implementation for Dart. The package focuses on the modern v4 specification and provides first-class support for PASERK key serialization utilities.

> **Status:** The library is under active development. While it already covers the full v4 feature set, breaking changes may still occur prior to a stable API freeze.

## What is PASETO?

PASETO is a cryptographic token format designed in 2018 as a safer alternative to JWT/JOSE. Key design principles include:

- **Fixed algorithms per version.** Each version specifies an explicit and limited list of algorithms, eliminating algorithm confusion attacks.
- **Strict separation of `local` (symmetric encryption) and `public` (public-key signatures) modes.** The format enforces the correct cryptographic workflow for each use case.
- **Well-defined token structure.** Parsers can reliably reject malformed payloads and avoid ambiguous encodings.
- **Modern cryptography.** Version 4 relies on XChaCha20-Poly1305, Ed25519, and BLAKE2b.

## Supported PASETO and PASERK Versions

| Version | Support | Notes |
|---------|---------|-------|
| v1      | No      | Legacy (RSA + AES-CTR) |
| v2      | No      | General-purpose (NaCl/libsodium) |
| v3      | No      | NIST-compliant |
| v4      | Yes     | Recommended for all new deployments |
| PASERK  | Yes     | Complete v4 coverage, including PIE, password-based, and seal families |

## PASERK Overview

PASERK (Platform-Agnostic Serialized Keys) standardizes how PASETO keys are encoded, exchanged, and protected. This package implements the full PASERK v4 surface area:

- `k4.local` and `k4.secret` for base serialization of symmetric and secret keys.
- `k4.local-wrap` and `k4.secret-wrap` for PIE-wrapped keys that can be stored encrypted at rest.
- `k4.local-pw` and `k4.secret-pw` for password-based transformations powered by Argon2id and XChaCha20.
- `k4.seal` for asymmetric sealing of keys to a recipient's public key.

Argon2id defaults to `timeCost = 2/3`, `memoryCost = 64 MiB`, and `parallelism = 1`. Tune these parameters to balance security and resource usage in your environment.

### Example: Serializing and Restoring a Key

```dart
import 'package:paseto_dart/paseto_dart.dart';

void main() {
  final localKey = K4LocalKey.generate();

  // Serialize for storage
  final serialized = localKey.encode();

  // Restore from string
  final restored = K4LocalKey.fromString(serialized);

  assert(restored.encode() == serialized);
}
```

Additional PASERK examples (PIE wraps, password-based transformations, and `k4.seal`) are available in `test/paserk`.

## Getting Started

Usage examples are available under the [example](example) directory. A typical public token issuance flow looks like this:

```dart
final package = Package(content: utf8.encode(jsonEncode(payload)));
final signedPayload = await PublicV4.sign(package, keyPair: keyPair);
final token = Token(
  header: PublicV4.header,
  payload: signedPayload,
  footer: null,
);

final tokenString = token.toTokenString;
```

## Choosing the Appropriate Token Type

| Token type | When to use | Advantages |
|------------|-------------|------------|
| `local`    | Protecting sensitive data or secrets at rest | Payload is encrypted and requires the shared key |
| `public`   | Authentication and authorization workflows | Verifiable by third parties without exposing the signing key |

## Operational Recommendations

1. Include an expiration claim (`exp`) in every authorization token.
2. Validate the token version before inspecting claims.
3. Securely manage symmetric and private keys; rotate them regularly.
4. Use `public` mode for access tokens and `local` mode for confidential data at rest.
5. Introduce replay mitigation (e.g., `jti` claims with server-side tracking) for critical operations.

## Building a Robust Authorization Flow

PASETO tokens do not include built-in replay protection. Adopt a layered architecture:

1. **Issue short-lived access tokens** (5–15 minutes) alongside long-lived refresh tokens stored on the server.
2. **Maintain server-side state** for issued token identifiers, session allowlists/denylists, and revocation triggers.
3. **Use single-use tokens** for high-risk actions. Include a unique `jti`, validate it on the server, and mark it as consumed after use.

## Additional Resources

- [Official PASETO specification](https://github.com/paseto-standard/paseto-spec)
- [Official website](https://paseto.io/)
- [Original PASETO announcement](https://paragonie.com/blog/2018/03/paseto-platform-agnostic-security-tokens-is-secure-alternative-jose-standards-jwt-etc)
- [JWT vs PASETO comparison](https://developer.okta.com/blog/2019/10/17/a-thorough-introduction-to-paseto)

## Testing

Integration tests rely on the [`python-paseto`](https://github.com/purificant/python-paseto) project to verify cross-language compatibility.

```bash
python -m pip install -r tool/python_requirements.txt
dart pub get
dart test
```
