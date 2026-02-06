// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
// SPDX-FileCopyrightText: 2026 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: MIT

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:paseto_dart/paseto_dart.dart';

import '../blake2/_index.dart' as blake2lib;

class K4LocalWrap extends PaserkKey {
  static const int nonceLength = 32;
  static const int tagLength = 32;
  static const int _splitLength = 56;
  static const int _encDomain = 0x80;
  static const int _authDomain = 0x81;

  static final Uint8List _headerBytes =
      Uint8List.fromList(utf8.encode(PaserkKey.k4LocalWrapPiePrefix));

  K4LocalWrap(Uint8List bytes) : super(bytes, PaserkKey.k4LocalWrapPiePrefix);

  static K4LocalWrap wrap(K4LocalKey key, K4LocalKey wrappingKey) {
    if (key.rawBytes.length != K4LocalKey.keyLength) {
      throw ArgumentError('Key must be exactly ${K4LocalKey.keyLength} bytes');
    }

    final nonce = _randomBytes(Random.secure(), nonceLength);
    final derived = _deriveEncryptionMaterial(wrappingKey.rawBytes, nonce);
    final encryptionKey = derived.sublist(0, 32);
    final xchachaNonce = derived.sublist(32);
    final authKey = _deriveAuthKey(wrappingKey.rawBytes, nonce);

    final cipher = XChaCha20();
    cipher.init(
      true,
      ParametersWithIV<KeyParameter>(
        KeyParameter(Uint8List.fromList(encryptionKey)),
        Uint8List.fromList(xchachaNonce),
      ),
    );
    final ciphertext = cipher.process(key.rawBytes);

    final tag = _calculateTag(nonce, ciphertext, authKey);

    final payload = Uint8List(tagLength + nonceLength + ciphertext.length)
      ..setAll(0, tag)
      ..setAll(tagLength, nonce)
      ..setAll(tagLength + nonceLength, ciphertext);

    return K4LocalWrap(payload);
  }

  static K4LocalKey unwrap(String wrappedKey, K4LocalKey wrappingKey) {
    if (!wrappedKey.startsWith(PaserkKey.k4LocalWrapPiePrefix)) {
      throw ArgumentError('Invalid k4.local-wrap format');
    }

    final payload = Uint8List.fromList(
      SafeBase64.decode(
        wrappedKey.substring(PaserkKey.k4LocalWrapPiePrefix.length),
      ),
    );

    if (payload.length < tagLength + nonceLength + K4LocalKey.keyLength) {
      throw ArgumentError('Invalid wrapped key length');
    }

    final tag = payload.sublist(0, tagLength);
    final nonce = payload.sublist(tagLength, tagLength + nonceLength);
    final ciphertext = payload.sublist(tagLength + nonceLength, payload.length);

    final authKey = _deriveAuthKey(wrappingKey.rawBytes, nonce);
    final expectedTag = _calculateTag(nonce, ciphertext, authKey);
    if (!_constantTimeEquals(tag, expectedTag)) {
      throw ArgumentError('Invalid authentication tag');
    }

    final derived = _deriveEncryptionMaterial(wrappingKey.rawBytes, nonce);
    final encryptionKey = derived.sublist(0, 32);
    final xchachaNonce = derived.sublist(32);

    final cipher = XChaCha20();
    cipher.init(
      false,
      ParametersWithIV<KeyParameter>(
        KeyParameter(Uint8List.fromList(encryptionKey)),
        Uint8List.fromList(xchachaNonce),
      ),
    );
    final decrypted = cipher.process(ciphertext);

    if (decrypted.length != K4LocalKey.keyLength) {
      throw ArgumentError('Decrypted key has invalid length');
    }

    return K4LocalKey(decrypted);
  }

  static Uint8List _deriveEncryptionMaterial(
    Uint8List wrappingKey,
    List<int> nonce,
  ) {
    final data = Uint8List(1 + nonce.length)
      ..[0] = _encDomain
      ..setAll(1, nonce);
    final blake = blake2lib.Blake2b(
      digestSize: _splitLength,
      key: wrappingKey,
    );
    return blake.process(data);
  }

  static Uint8List _deriveAuthKey(Uint8List wrappingKey, List<int> nonce) {
    final data = Uint8List(1 + nonce.length)
      ..[0] = _authDomain
      ..setAll(1, nonce);
    final blake = blake2lib.Blake2b(
      digestSize: tagLength,
      key: wrappingKey,
    );
    return blake.process(data);
  }

  static Uint8List _calculateTag(
    List<int> nonce,
    List<int> ciphertext,
    Uint8List authKey,
  ) {
    final message = Uint8List(
      _headerBytes.length + nonce.length + ciphertext.length,
    )
      ..setAll(0, _headerBytes)
      ..setAll(_headerBytes.length, nonce)
      ..setAll(_headerBytes.length + nonce.length, ciphertext);
    final blake = blake2lib.Blake2b(
      digestSize: tagLength,
      key: authKey,
    );
    return blake.process(message);
  }

  static bool _constantTimeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    var result = 0;
    for (var i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result == 0;
  }

  static Uint8List _randomBytes(Random random, int length) {
    final bytes = Uint8List(length);
    for (var i = 0; i < length; i++) {
      bytes[i] = random.nextInt(256);
    }
    return bytes;
  }
}
