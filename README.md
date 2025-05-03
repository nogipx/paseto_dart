# paseto_dart

Dart implementation of [PASETO](https://paseto.io) (Platform-Agnostic Security Tokens) — a modern cryptographically secure alternative to JWT.

## What is PASETO

PASETO is a protocol for creating secure access tokens, developed in 2018 as an alternative to JWT/JOSE, addressing its major security flaws:

- **Fixed set of algorithms** in each version — eliminates vulnerabilities related to algorithm selection
- **Strict separation of modes** into `local` (encryption) and `public` (signing) — prevents confusion
- **Strict format specification** — minimizes implementation errors
- **Modern cryptography** — uses ChaCha20-Poly1305, Ed25519, ECDSA, and other proven algorithms

Example of a PASETO token:
```
v4.public.eyJleHAiOiIyMDIyLTAxLTAxVDAwOjAwOjAwKzAwOjAwIiwiaWF0IjoiMjAyMS0xMi0zMVQyMzo1OTo1OSswMDowMCIsInN1YiI6ImpvaG5kb2UiLCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIn03FSq9Vfr0WMUEubQxSgEJUPGRAdlfLsrfT_i1RPJjNUHZ6JpjuWuP4sSAHzLmD92h-ar5CEJj2V00Mj_GlEw
```

## 🚀 Installation

```yaml
dependencies:
  paseto_dart: ^1.0.0
```

## 📋 Supported PASETO Versions

| Version | Support | Description |
|---------|---------|-------------|
| v1      | ❌      | Legacy (RSA + AES-CTR) - not supported |
| v2      | ✅      | General purpose (NaCl/libsodium) |
| v3      | ✅      | NIST-compliant |
| v4      | ✅      | Modern (recommended) |
| PASERK  | ❌      | PASETO key representation format |

## 🔐 Quick Start

### Creating and Verifying a Signed Token (public):

```dart
import 'dart:convert';
import 'package:paseto_dart/paseto_dart.dart';

// Creating keys
final keyPair = await Ed25519().newKeyPair();

// Creating a token with data (e.g., for authorization)
final userData = {
  'sub': 'user123',
  'name': 'John Doe',
  'exp': DateTime.now().add(Duration(hours: 1)).millisecondsSinceEpoch ~/ 1000
};

// Signing the token
final message = await Message.signString(
  jsonEncode(userData),
  version: Version.v4,
  keyPair: keyPair,
);
final token = message.toToken.toTokenString;

// Verifying and reading the token
final receivedToken = await Token.fromString(token);
final verifiedMessage = await receivedToken.verifyPublicMessage(
  publicKey: keyPair.publicKey
);
final payload = jsonDecode(verifiedMessage.stringContent!);
print('User ID: ${payload['sub']}');
```

### Encrypting and Decrypting Data (local):

```dart
import 'dart:convert';
import 'dart:math';
import 'package:paseto_dart/paseto_dart.dart';

// Creating a secret key
final random = Random.secure();
final secretKey = SecretKeyData(
  List<int>.generate(32, (_) => random.nextInt(256))
);

// Encrypting data
final sensitiveData = {'secret': 'Confidential information'};
final encrypted = await Message.encryptString(
  jsonEncode(sensitiveData),
  version: Version.v4,
  secretKey: secretKey,
);
final encryptedToken = encrypted.toToken.toTokenString;

// Decrypting data
final receivedToken = await Token.fromString(encryptedToken);
final decrypted = await receivedToken.decryptLocalMessage(secretKey: secretKey);
final decryptedData = jsonDecode(decrypted.stringContent!);
print('Secret: ${decryptedData['secret']}');
```

## 📚 Selection Guide

| Token Type | When to Use | Advantages |
|------------|-------------|------------|
| **local**  | - Protecting sensitive data<br> - Storing secrets | - Data is encrypted<br> - Only accessible with the key |
| **public** | - Authorization<br> - Authentication | - Authentication without the secret key<br> - Compatible with JWT approach |

## 🔑 Best Practices

1. **Use v4** for new projects
2. **Include expiration time** (`exp`) in authorization tokens
3. **Always verify the token version** before use
4. **Store keys securely**
5. **For authorization tokens** use `public` mode
6. **For data protection** use `local` mode

## ⚠️ Proper Authorization Implementation

> **Important!** PASETO tokens are not designed for reuse as long-term access tokens.

PASETO does not have built-in protection against replay attacks (token reuse). If a token is intercepted, an attacker can use it until it expires.

### Recommended Authorization Architecture

1. **Use a two-tier token system**:
   - Short-lived PASETO access tokens (5-15 minutes)
   - Long-lived refresh tokens (stored in the server database)

```dart
// Example of creating tokens in a two-tier authorization system
Future<AuthTokens> createAuthTokens(User user) async {
  // Short-lived access token
  final accessTokenData = {
    'sub': user.id,
    'exp': DateTime.now().add(Duration(minutes: 15)).millisecondsSinceEpoch ~/ 1000,
    'jti': generateUniqueId(), // Token ID for protection against reuse
  };
  
  final accessToken = await Message.signString(
    jsonEncode(accessTokenData),
    version: Version.v4,
    keyPair: authKeyPair,
  );
  
  // Generating a refresh token and storing it in the database
  final refreshToken = generateSecureRandomString();
  await storeRefreshTokenInDatabase(user.id, refreshToken);
  
  return AuthTokens(
    accessToken: accessToken.toToken.toTokenString,
    refreshToken: refreshToken,
  );
}
```

2. **Add server-side state verification**:
   - Store IDs of used tokens
   - Maintain a whitelist/blacklist of active sessions
   - Implement a mechanism for immediate token revocation

```dart
// Example of token validation on the server
Future<bool> validateAccessToken(String tokenString) async {
  try {
    final token = await Token.fromString(tokenString);
    final message = await token.verifyPublicMessage(publicKey: authPublicKey);
    final payload = jsonDecode(message.stringContent!);
    
    // Checking expiration time
    final expiration = payload['exp'] as int;
    if (DateTime.now().millisecondsSinceEpoch ~/ 1000 > expiration) {
      return false; // Token expired
    }
    
    // Checking if the token has already been used (for one-time operations)
    final tokenId = payload['jti'] as String;
    if (await wasTokenAlreadyUsed(tokenId)) {
      return false; // Token already used
    }
    
    // Checking if the session has been revoked
    final userId = payload['sub'] as String;
    if (await isUserSessionRevoked(userId)) {
      return false; // Session revoked by administrator
    }
    
    // Optional: for critical operations, mark the token as used
    // await markTokenAsUsed(tokenId);
    
    return true;
  } catch (e) {
    return false; // Validation error
  }
}
```

3. **For critical operations, use one-time tokens**:
   - Add a unique identifier (`jti`) to the payload
   - Check on the server if the token has already been used
   - After use, add the token ID to the list of used tokens

### What Not to Do

❌ **Don't use PASETO as permanent access tokens**:
```dart
// INCORRECT: Using a long-lived token for all requests
final userData = {
  'sub': 'user123',
  'exp': DateTime.now().add(Duration(days: 30)).millisecondsSinceEpoch ~/ 1000
};
```

❌ **Don't rely solely on token expiration for security**:
```dart
// INCORRECT: No additional server-side checks
if (tokenData['exp'] > currentTimestamp) {
  // Granting access based only on expiration time
  grantAccess();
}
```

## ⚙️ PASETO Implementations in Other Languages

PASETO has implementations in many languages:

- JavaScript/TypeScript: [paseto.js](https://github.com/panva/paseto)
- PHP: [paragonie/paseto](https://github.com/paragonie/paseto)
- Go: [o1egl/paseto](https://github.com/o1egl/paseto)
- Rust: [brycx/pasetors](https://github.com/brycx/pasetors)
- Python: [pyca/paseto](https://github.com/pyca/paseto)
- Java: [paseto4j](https://github.com/atholbro/paseto4j)
- C#/.NET: [dustinsoftware/paseto.net](https://github.com/dustinsoftware/paseto.net)
- Ruby: [mguymon/paseto.rb](https://github.com/mguymon/paseto.rb)
- Elixir: [mbramson/pigeon_paseto](https://github.com/mbramson/pigeon_paseto)
- Kotlin: [paseto-kotlin](https://github.com/dstraube/paseto-kotlin)

## 📖 Useful Links

- [Official PASETO Specification](https://github.com/paseto-standard/paseto-spec)
- [Official Website](https://paseto.io/)
- [Article about PASETO by its author](https://paragonie.com/blog/2018/03/paseto-platform-agnostic-security-tokens-is-secure-alternative-jose-standards-jwt-etc)
- [Comparison with JWT](https://developer.okta.com/blog/2019/10/17/a-thorough-introduction-to-paseto)