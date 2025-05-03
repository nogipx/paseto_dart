// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'package:paseto_dart/paseto_dart.dart';

/// Расширение для извлечения байтов из SecretKey
extension SecretKeyExtensions on SecretKey {
  /// Извлекает байты из различных реализаций SecretKey
  Future<List<int>> extractBytes() async {
    if (this is SecretKeyData) {
      return (this as SecretKeyData).bytes;
    } else {
      throw UnsupportedError(
          'Cannot extract bytes from this type of SecretKey');
    }
  }
}
