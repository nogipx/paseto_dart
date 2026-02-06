// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
// SPDX-FileCopyrightText: 2026 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: MIT

import 'dart:convert';
import 'dart:typed_data';

import '../blake2/_index.dart' as blake2lib;
import '../utils/base64_ext.dart';
import 'k4_secret.dart';
import 'paserk_key.dart';

class K4Sid extends PaserkKey {
  static const int hashLength = 33; // BLAKE2b-264 = 33 bytes
  static const _prefix = 'k4.sid.';

  K4Sid(Uint8List bytes) : super(bytes, PaserkKey.k4SidPrefix) {
    if (bytes.length != hashLength) {
      throw ArgumentError('K4Sid must be exactly $hashLength bytes');
    }
  }

  static K4Sid fromKey(K4SecretKey key) {
    final paserk = key.toString(); // Получаем полный PASERK ключа
    final input =
        Uint8List.fromList(utf8.encode(_prefix) + utf8.encode(paserk));

    // Используем BLAKE2b-264 как указано в спецификации
    final blake2b = blake2lib.Blake2b(
      digestSize: hashLength, // 33 bytes для BLAKE2b-264
    );

    return K4Sid(blake2b.process(input));
  }

  static K4Sid fromString(String encoded) {
    if (!encoded.startsWith(PaserkKey.k4SidPrefix)) {
      throw ArgumentError('Invalid k4.sid format');
    }

    final decoded =
        SafeBase64.decode(encoded.substring(PaserkKey.k4SidPrefix.length));
    if (decoded.length != hashLength) {
      throw ArgumentError('Decoded k4.sid must be exactly $hashLength bytes');
    }
    return K4Sid(Uint8List.fromList(decoded));
  }

  @override
  String toString() {
    return PaserkKey.k4SidPrefix + SafeBase64.encode(rawBytes);
  }

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! K4Sid) return false;

    // Используем константное по времени сравнение
    if (rawBytes.length != other.rawBytes.length) return false;
    var result = 0;
    for (var i = 0; i < rawBytes.length; i++) {
      result |= rawBytes[i] ^ other.rawBytes[i];
    }
    return result == 0;
  }

  @override
  int get hashCode => Object.hash(
        PaserkKey.k4SidPrefix,
        Object.hashAll(rawBytes),
      );
}
