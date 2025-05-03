// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'package:meta/meta.dart';
import 'package:paseto_dart/common/crypto_types.dart';

@immutable
class PasetoException implements Exception {
  const PasetoException(this.message);
  final String message;

  @override
  String toString() => 'PasetoException: $message';
}

/// Исключение для ошибок криптографии
@immutable
class CryptographyException implements Exception {
  const CryptographyException(this.message);
  final String message;

  @override
  String toString() => 'CryptographyException: $message';
}

/// Исключение возникающее при неправильном MAC
@immutable
class SecretBoxAuthenticationError extends Error {
  SecretBoxAuthenticationError(this.message);
  final String message;

  @override
  String toString() => 'SecretBoxAuthenticationError: $message';
}

/// Исключение возникающее при неправильной подписи
@immutable
class SignatureVerificationError implements Exception {
  const SignatureVerificationError(this.message);
  final String message;

  @override
  String toString() => 'SignatureVerificationError: $message';
}

/// Интерфейс для подписи сообщений
@immutable
abstract class Signature {
  const Signature();

  /// Получить байты подписи
  List<int> get bytes;

  /// Получить публичный ключ подписи
  PublicKey get publicKey;
}

/// Обертка для Signature, чтобы избежать конфликтов с PointyCastle
@immutable
class PasetoSignature implements Signature {
  const PasetoSignature(this._bytes, {required this.publicKey});

  final List<int> _bytes;

  @override
  final PublicKey publicKey;

  @override
  List<int> get bytes => _bytes;

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! Signature) return false;

    if (bytes.length != other.bytes.length) return false;

    for (var i = 0; i < bytes.length; i++) {
      if (bytes[i] != other.bytes[i]) return false;
    }

    return true;
  }

  @override
  int get hashCode => Object.hashAll(bytes);
}
