// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
// SPDX-FileCopyrightText: 2026 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: MIT

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'k4_secret.dart';
import 'paserk_key.dart';

class K4PublicKey extends PaserkKey {
  static const int keyLength = 32;

  K4PublicKey(Uint8List bytes) : super(bytes, PaserkKey.k4PublicPrefix) {
    if (bytes.length != keyLength) {
      throw ArgumentError('K4PublicKey must be exactly $keyLength bytes');
    }
  }

  static K4PublicKey fromString(String encoded) {
    return K4PublicKey(PaserkKey.decode(encoded, PaserkKey.k4PublicPrefix));
  }

  static Future<K4PublicKey> fromSecretKey(K4SecretKey secretKey) async {
    return K4PublicKey(secretKey.publicKeyBytes);
  }

  Future<SimplePublicKey> toPublicKey() async {
    return SimplePublicKey(
      rawBytes,
      type: KeyPairType.ed25519,
    );
  }
}
