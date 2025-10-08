// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: MIT

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../utils/base64_ext.dart';
import 'paserk_key.dart';

class K4SecretKey extends PaserkKey {
  static const int keyLength = 64; // 32 bytes seed + 32 bytes public key

  K4SecretKey(Uint8List bytes) : super(bytes, PaserkKey.k4SecretPrefix) {
    if (bytes.length != keyLength) {
      throw ArgumentError(
          'K4SecretKey must be exactly $keyLength bytes (32-byte seed + 32-byte public key)');
    }
  }

  static K4SecretKey fromHex(String hex) {
    final bytes = _hexToBytes(hex);
    if (bytes.length != keyLength) {
      throw ArgumentError(
          'K4SecretKey must be exactly $keyLength bytes (32-byte seed + 32-byte public key)');
    }
    return K4SecretKey(bytes);
  }

  static K4SecretKey fromString(String encoded) {
    if (!encoded.startsWith(PaserkKey.k4SecretPrefix)) {
      throw ArgumentError('Invalid k4.secret key format');
    }

    final decoded =
        SafeBase64.decode(encoded.substring(PaserkKey.k4SecretPrefix.length));
    if (decoded.length != keyLength) {
      throw ArgumentError(
          'Decoded k4.secret key must be exactly $keyLength bytes');
    }
    return K4SecretKey(Uint8List.fromList(decoded));
  }

  /// Возвращает seed часть ключа (первые 32 байта)
  Uint8List get seed => rawBytes.sublist(0, 32);

  /// Возвращает публичную часть ключа (последние 32 байта)
  Uint8List get publicKeyBytes => rawBytes.sublist(32);

  @override
  String toString() {
    return PaserkKey.k4SecretPrefix + SafeBase64.encode(rawBytes);
  }

  static Uint8List _hexToBytes(String hex) {
    if (hex.length % 2 != 0) {
      throw ArgumentError('Hex string must have even length');
    }
    var result = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < hex.length; i += 2) {
      var num = int.parse(hex.substring(i, i + 2), radix: 16);
      result[i ~/ 2] = num;
    }
    return result;
  }

  Future<SimplePublicKey> get publicKey async {
    // Используем последние 32 байта как публичный ключ
    return SimplePublicKey(
      publicKeyBytes,
      type: KeyPairType.ed25519,
    );
  }
}
