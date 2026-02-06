// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
// SPDX-FileCopyrightText: 2026 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: MIT

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:paseto_dart/paseto_dart.dart';

import '../blake2/_index.dart' as blake2lib;

class K4LocalPw extends PaserkKey {
  static const int saltLength = 16;
  static const int nonceLength = 24;
  static const int tagLength = 32;
  static const int defaultMemoryCost = 64 * 1024 * 1024; // 64 MiB
  static const int defaultTimeCost = 2;
  static const int defaultParallelism = 1;

  K4LocalPw(Uint8List bytes) : super(bytes, PaserkKey.k4LocalPwPrefix);

  static Future<K4LocalPw> wrap(
    K4LocalKey key,
    String password, {
    int memoryCost = defaultMemoryCost,
    int timeCost = defaultTimeCost,
    int parallelism = defaultParallelism,
  }) async {
    if (key.rawBytes.length != K4LocalKey.keyLength) {
      throw ArgumentError(
        'Key must be exactly ${K4LocalKey.keyLength} bytes',
      );
    }
    if (memoryCost <= 0 || memoryCost % 1024 != 0) {
      throw ArgumentError('memoryCost must be a positive multiple of 1024');
    }
    if (timeCost <= 0) {
      throw ArgumentError('timeCost must be positive');
    }
    if (parallelism <= 0) {
      throw ArgumentError('parallelism must be positive');
    }

    final random = Random.secure();
    final salt = _randomBytes(random, saltLength);
    final preKey = await _derivePreKey(
      password,
      salt,
      memoryCost,
      timeCost,
      parallelism,
    );

    final encKey = _deriveKeyMaterial(preKey, 0xff);
    final authKey = _deriveKeyMaterial(preKey, 0xfe);

    final nonce = _randomBytes(random, nonceLength);
    final encrypted = _encrypt(encKey, nonce, key.rawBytes);

    final tag = _calculateTag(
      PaserkKey.k4LocalPwPrefix,
      salt,
      memoryCost,
      timeCost,
      parallelism,
      nonce,
      encrypted,
      authKey,
    );

    final payloadLength =
        saltLength + 8 + 4 + 4 + nonceLength + encrypted.length + tagLength;
    final payload = Uint8List(payloadLength);
    var offset = 0;
    payload.setAll(offset, salt);
    offset += saltLength;
    payload.setAll(offset, _uint64ToBytes(memoryCost));
    offset += 8;
    payload.setAll(offset, _uint32ToBytes(timeCost));
    offset += 4;
    payload.setAll(offset, _uint32ToBytes(parallelism));
    offset += 4;
    payload.setAll(offset, nonce);
    offset += nonceLength;
    payload.setAll(offset, encrypted);
    offset += encrypted.length;
    payload.setAll(offset, tag);

    return K4LocalPw(payload);
  }

  static Future<K4LocalKey> unwrap(
    String serialized,
    String password,
  ) async {
    if (!serialized.startsWith(PaserkKey.k4LocalPwPrefix)) {
      throw ArgumentError('Invalid k4.local-pw format');
    }

    final data = Uint8List.fromList(
      SafeBase64.decode(serialized.substring(PaserkKey.k4LocalPwPrefix.length)),
    );

    if (data.length <
        saltLength +
            8 +
            4 +
            4 +
            nonceLength +
            K4LocalKey.keyLength +
            tagLength) {
      throw ArgumentError('Invalid wrapped key length');
    }

    var offset = 0;
    final salt = data.sublist(offset, offset + saltLength);
    offset += saltLength;
    final memoryCost = _bytesToUint64(data.sublist(offset, offset + 8));
    offset += 8;
    final timeCost = _bytesToUint32(data.sublist(offset, offset + 4));
    offset += 4;
    final parallelism = _bytesToUint32(data.sublist(offset, offset + 4));
    offset += 4;
    final nonce = data.sublist(offset, offset + nonceLength);
    offset += nonceLength;
    final encrypted = data.sublist(offset, data.length - tagLength);
    final tag = data.sublist(data.length - tagLength);

    if (memoryCost <= 0 || memoryCost % 1024 != 0) {
      throw ArgumentError('Invalid memoryCost value');
    }
    if (timeCost <= 0 || parallelism <= 0) {
      throw ArgumentError('Invalid PBKW parameters');
    }

    final preKey = await _derivePreKey(
      password,
      salt,
      memoryCost,
      timeCost,
      parallelism,
    );

    final encKey = _deriveKeyMaterial(preKey, 0xff);
    final authKey = _deriveKeyMaterial(preKey, 0xfe);

    final expectedTag = _calculateTag(
      PaserkKey.k4LocalPwPrefix,
      salt,
      memoryCost,
      timeCost,
      parallelism,
      nonce,
      encrypted,
      authKey,
    );

    if (!_constantTimeEquals(tag, expectedTag)) {
      throw ArgumentError('Invalid authentication tag');
    }

    final decrypted = _decrypt(encKey, nonce, encrypted);
    if (decrypted.length != K4LocalKey.keyLength) {
      throw ArgumentError('Decrypted key has invalid length');
    }

    return K4LocalKey(decrypted);
  }

  static Future<Uint8List> _derivePreKey(
    String password,
    List<int> salt,
    int memoryCost,
    int timeCost,
    int parallelism,
  ) async {
    final algorithm = Argon2id(
      memory: memoryCost ~/ 1024,
      iterations: timeCost,
      parallelism: parallelism,
      hashLength: 32,
    );

    final secretKey = await algorithm.deriveKeyFromPassword(
      password: password,
      nonce: salt,
    );
    return Uint8List.fromList(await secretKey.extractBytes());
  }

  static Uint8List _deriveKeyMaterial(List<int> preKey, int prefix) {
    final blake2b = blake2lib.Blake2b(digestSize: 32);
    final input = Uint8List(preKey.length + 1)
      ..[0] = prefix
      ..setAll(1, preKey);
    return blake2b.process(input);
  }

  static Uint8List _calculateTag(
    String header,
    List<int> salt,
    int memoryCost,
    int timeCost,
    int parallelism,
    List<int> nonce,
    List<int> encrypted,
    List<int> authKey,
  ) {
    final blake2b = blake2lib.Blake2b(
      digestSize: tagLength,
      key: Uint8List.fromList(authKey),
    );
    final message = Uint8List(
      header.length + saltLength + 8 + 4 + 4 + nonceLength + encrypted.length,
    );
    var offset = 0;
    final headerBytes = utf8.encode(header);
    message.setAll(offset, headerBytes);
    offset += headerBytes.length;
    message.setAll(offset, salt);
    offset += saltLength;
    message.setAll(offset, _uint64ToBytes(memoryCost));
    offset += 8;
    message.setAll(offset, _uint32ToBytes(timeCost));
    offset += 4;
    message.setAll(offset, _uint32ToBytes(parallelism));
    offset += 4;
    message.setAll(offset, nonce);
    offset += nonceLength;
    message.setAll(offset, encrypted);
    return blake2b.process(message);
  }

  static Uint8List _encrypt(List<int> encKey, List<int> nonce, List<int> data) {
    final cipher = XChaCha20();
    final keyParam = KeyParameter(Uint8List.fromList(encKey));
    cipher.init(
      true,
      ParametersWithIV<KeyParameter>(keyParam, Uint8List.fromList(nonce)),
    );
    return cipher.process(Uint8List.fromList(data));
  }

  static Uint8List _decrypt(List<int> encKey, List<int> nonce, List<int> data) {
    final cipher = XChaCha20();
    final keyParam = KeyParameter(Uint8List.fromList(encKey));
    cipher.init(
      false,
      ParametersWithIV<KeyParameter>(keyParam, Uint8List.fromList(nonce)),
    );
    return cipher.process(Uint8List.fromList(data));
  }

  static Uint8List _randomBytes(Random random, int length) {
    final bytes = Uint8List(length);
    for (var i = 0; i < length; i++) {
      bytes[i] = random.nextInt(256);
    }
    return bytes;
  }

  static List<int> _uint64ToBytes(int value) {
    final bytes = Uint8List(8);
    for (var i = 7; i >= 0; i--) {
      bytes[7 - i] = (value >> (i * 8)) & 0xff;
    }
    return bytes;
  }

  static List<int> _uint32ToBytes(int value) {
    final bytes = Uint8List(4);
    for (var i = 3; i >= 0; i--) {
      bytes[3 - i] = (value >> (i * 8)) & 0xff;
    }
    return bytes;
  }

  static int _bytesToUint64(List<int> bytes) {
    if (bytes.length != 8) {
      throw ArgumentError('Expected 8 bytes for uint64');
    }
    var value = 0;
    for (final byte in bytes) {
      value = (value << 8) | (byte & 0xff);
    }
    return value;
  }

  static int _bytesToUint32(List<int> bytes) {
    if (bytes.length != 4) {
      throw ArgumentError('Expected 4 bytes for uint32');
    }
    var value = 0;
    for (final byte in bytes) {
      value = (value << 8) | (byte & 0xff);
    }
    return value;
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
