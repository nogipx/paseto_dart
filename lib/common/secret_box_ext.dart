// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'dart:typed_data';
import 'package:paseto_dart/common/crypto_types.dart';

extension SecretBoxNonce on SecretBox {
  SecretBox withNonce(Uint8List nonce) {
    return SecretBox(
      cipherText,
      nonce: nonce.toList(),
      mac: mac,
    );
  }
}
