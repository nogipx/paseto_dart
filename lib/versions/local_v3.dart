// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'package:meta/meta.dart';
import 'package:paseto_dart/paseto_dart.dart';

/// Класс для обработки ошибок аутентификации
class SecretBoxAuthenticationError implements Exception {
  SecretBoxAuthenticationError(this.message);
  final String message;

  @override
  String toString() => 'SecretBoxAuthenticationError: $message';
}

/// Реализация PASETO v3.local токенов согласно официальной спецификации
/// Использует AES-256-CTR с HMAC-SHA-384
@immutable
class LocalV3 {
  static const header = Header(
    version: Version.v3,
    purpose: Purpose.local,
  );
  static const nonceLength = 32;
  static const macLength = 48;

  /// Расшифровывает PASETO v3.local токен
  static Future<Package> decrypt(
    Token token, {
    required SecretKey secretKey,
    List<int>? implicit,
  }) async {
    throw UnimplementedError();
  }

  /// Шифрует данные и создает PASETO v3.local токен
  static Future<Payload> encrypt(
    Package package, {
    required SecretKey secretKey,
    List<int>? implicit,
  }) async {
    throw UnimplementedError();
  }
}
