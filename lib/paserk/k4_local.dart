// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: MIT

import 'dart:math';
import 'dart:typed_data';

import 'paserk_key.dart';

class K4LocalKey extends PaserkKey {
  static const int keyLength = 32;

  K4LocalKey(Uint8List bytes) : super(bytes, PaserkKey.k4LocalPrefix) {
    if (bytes.length != keyLength) {
      throw ArgumentError('K4LocalKey must be exactly $keyLength bytes');
    }
  }

  static K4LocalKey generate() {
    final random = Random.secure();
    final bytes = Uint8List(keyLength);
    for (var i = 0; i < keyLength; i++) {
      bytes[i] = random.nextInt(256);
    }
    return K4LocalKey(bytes);
  }

  static K4LocalKey fromString(String encoded) {
    return K4LocalKey(PaserkKey.decode(encoded, PaserkKey.k4LocalPrefix));
  }
}
