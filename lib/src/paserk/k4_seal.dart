// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
// SPDX-FileCopyrightText: 2026 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: MIT

import 'dart:convert';
import 'dart:typed_data';

import 'package:paseto_dart/paseto_dart.dart';

import '../blake2/_index.dart' as blake2lib;

class K4Seal extends PaserkKey {
  static const int tagLength = 32;
  static const int ephemeralPublicKeyLength = 32;

  K4Seal(Uint8List bytes) : super(bytes, PaserkKey.k4SealPrefix);

  static Future<K4Seal> seal(K4LocalKey key, K4PublicKey wrappingKey) async {
    if (key.rawBytes.length != K4LocalKey.keyLength) {
      throw ArgumentError(
        'Key must be exactly ${K4LocalKey.keyLength} bytes',
      );
    }

    final xpk = _ed25519PublicToX25519(wrappingKey.rawBytes);
    final headerBytes = utf8.encode(PaserkKey.k4SealPrefix);

    final x25519 = X25519();
    final ephemeralKeyPair = await x25519.newKeyPair();
    final ephemeralPublic = await ephemeralKeyPair.extractPublicKey();
    final epkBytes = Uint8List.fromList(ephemeralPublic.bytes);

    final sharedSecret = await x25519.sharedSecretKey(
      keyPair: ephemeralKeyPair,
      remotePublicKey: SimplePublicKey(xpk, type: KeyPairType.x25519),
    );
    final xk = Uint8List.fromList(await sharedSecret.extractBytes());

    final encKey = _derivePkeKey(0x01, headerBytes, xk, epkBytes, xpk);
    final authKey = _derivePkeKey(0x02, headerBytes, xk, epkBytes, xpk);
    final nonce = _deriveNonce(epkBytes, xpk);

    final encrypted = _encrypt(encKey, nonce, key.rawBytes);
    final tag = _computeSealTag(headerBytes, epkBytes, encrypted, authKey);

    final payload =
        Uint8List(tagLength + ephemeralPublicKeyLength + encrypted.length)
          ..setAll(0, tag)
          ..setAll(tagLength, epkBytes)
          ..setAll(tagLength + ephemeralPublicKeyLength, encrypted);

    return K4Seal(payload);
  }

  static Future<K4LocalKey> unseal(
    String serialized,
    K4SecretKey secretKey,
  ) async {
    if (!serialized.startsWith(PaserkKey.k4SealPrefix)) {
      throw ArgumentError('Invalid k4.seal format');
    }

    final data = Uint8List.fromList(
      SafeBase64.decode(serialized.substring(PaserkKey.k4SealPrefix.length)),
    );

    if (data.length !=
        tagLength + ephemeralPublicKeyLength + K4LocalKey.keyLength) {
      throw ArgumentError('Invalid sealed key length');
    }

    final tag = data.sublist(0, tagLength);
    final epk = data.sublist(tagLength, tagLength + ephemeralPublicKeyLength);
    final encrypted = data.sublist(tagLength + ephemeralPublicKeyLength);

    final xsk = await _ed25519SecretToX25519(secretKey.rawBytes);
    final xpk = _ed25519PublicToX25519(secretKey.publicKeyBytes);
    final headerBytes = utf8.encode(PaserkKey.k4SealPrefix);

    final x25519 = X25519();
    final x25519KeyPair = SimpleKeyPairData(
      xsk,
      publicKey: SimplePublicKey(xpk, type: KeyPairType.x25519),
      type: KeyPairType.x25519,
    );

    final sharedSecret = await x25519.sharedSecretKey(
      keyPair: x25519KeyPair,
      remotePublicKey: SimplePublicKey(epk, type: KeyPairType.x25519),
    );
    final xk = Uint8List.fromList(await sharedSecret.extractBytes());

    final authKey = _derivePkeKey(0x02, headerBytes, xk, epk, xpk);
    final expectedTag = _computeSealTag(headerBytes, epk, encrypted, authKey);

    if (!_constantTimeEquals(tag, expectedTag)) {
      throw ArgumentError('Invalid authentication tag');
    }

    final encKey = _derivePkeKey(0x01, headerBytes, xk, epk, xpk);
    final nonce = _deriveNonce(epk, xpk);
    final decrypted = _decrypt(encKey, nonce, encrypted);

    if (decrypted.length != K4LocalKey.keyLength) {
      throw ArgumentError('Decrypted key has invalid length');
    }

    return K4LocalKey(decrypted);
  }

  static Uint8List _derivePkeKey(
    int prefix,
    List<int> header,
    List<int> sharedSecret,
    List<int> epk,
    List<int> xpk,
  ) {
    final blake2b = blake2lib.Blake2b(digestSize: 32);
    final data = Uint8List(
        1 + header.length + sharedSecret.length + epk.length + xpk.length)
      ..[0] = prefix
      ..setAll(1, header)
      ..setAll(1 + header.length, sharedSecret)
      ..setAll(1 + header.length + sharedSecret.length, epk)
      ..setAll(1 + header.length + sharedSecret.length + epk.length, xpk);
    return blake2b.process(data);
  }

  static Uint8List _deriveNonce(List<int> epk, List<int> xpk) {
    final blake2b = blake2lib.Blake2b(digestSize: 24);
    final input = Uint8List(epk.length + xpk.length)
      ..setAll(0, epk)
      ..setAll(epk.length, xpk);
    return blake2b.process(input);
  }

  static Uint8List _computeSealTag(
    List<int> header,
    List<int> epk,
    List<int> encrypted,
    List<int> authKey,
  ) {
    final blake2b = blake2lib.Blake2b(
      digestSize: tagLength,
      key: Uint8List.fromList(authKey),
    );
    final message = Uint8List(header.length + epk.length + encrypted.length)
      ..setAll(0, header)
      ..setAll(header.length, epk)
      ..setAll(header.length + epk.length, encrypted);
    return blake2b.process(message);
  }

  static Uint8List _encrypt(List<int> key, List<int> nonce, List<int> data) {
    final cipher = XChaCha20();
    final keyParam = KeyParameter(Uint8List.fromList(key));
    cipher.init(
      true,
      ParametersWithIV<KeyParameter>(keyParam, Uint8List.fromList(nonce)),
    );
    return cipher.process(Uint8List.fromList(data));
  }

  static Uint8List _decrypt(List<int> key, List<int> nonce, List<int> data) {
    final cipher = XChaCha20();
    final keyParam = KeyParameter(Uint8List.fromList(key));
    cipher.init(
      false,
      ParametersWithIV<KeyParameter>(keyParam, Uint8List.fromList(nonce)),
    );
    return cipher.process(Uint8List.fromList(data));
  }

  static Uint8List _ed25519PublicToX25519(Uint8List edPublic) {
    if (edPublic.length != 32) {
      throw ArgumentError('Ed25519 public key must be 32 bytes');
    }
    final prime = BigInt.parse(
      '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed',
      radix: 16,
    );
    final mask = (BigInt.one << 255) - BigInt.one;
    final y = _decodeLittleEndian(edPublic) & mask;
    final numerator = (BigInt.one + y) % prime;
    final denominator = (BigInt.one - y) % prime;
    if (denominator == BigInt.zero) {
      throw ArgumentError('Invalid Ed25519 public key');
    }
    final inverse = denominator.modPow(prime - BigInt.from(2), prime);
    final x = (numerator * inverse) % prime;
    return _encodeLittleEndian(x, 32);
  }

  static Future<Uint8List> _ed25519SecretToX25519(Uint8List edSecret) async {
    if (edSecret.length != 64) {
      throw ArgumentError('Ed25519 secret key must be 64 bytes');
    }
    final seed = edSecret.sublist(0, 32);
    final hash = await Sha512().hash(seed);
    final bytes = Uint8List.fromList(hash.bytes.sublist(0, 32));
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    return bytes;
  }

  static BigInt _decodeLittleEndian(Uint8List bytes) {
    var result = BigInt.zero;
    for (var i = bytes.length - 1; i >= 0; i--) {
      result = (result << 8) | BigInt.from(bytes[i]);
    }
    return result;
  }

  static Uint8List _encodeLittleEndian(BigInt value, int length) {
    final bytes = Uint8List(length);
    var temp = value;
    for (var i = 0; i < length; i++) {
      bytes[i] = (temp & BigInt.from(0xff)).toInt();
      temp = temp >> 8;
    }
    return bytes;
  }

  static bool _constantTimeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    var result = 0;
    for (var i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result == 0;
  }
}
