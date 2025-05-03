// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'package:meta/meta.dart';
import 'package:paseto_dart/paseto_dart.dart';

/// Реализация PASETO v2.local токенов согласно официальной спецификации
/// Использует XChaCha20-Poly1305 для аутентифицированного шифрования
@immutable
class LocalV2 {
  static const header = Header(
    version: Version.v2,
    purpose: Purpose.local,
  );
  static const nonceLength = 24;
  static const macLength = 16; // Poly1305 MAC длиной 16 байт

  /// Расшифровывает PASETO v2.local токен и проверяет его целостность
  static Future<Package> decrypt(
    Token token, {
    required SecretKey secretKey,
  }) async {
    // Инициализируем регистрацию алгоритмов
    PasetoRegistryInitializer.initV2Local();

    // Проверка версии и purpose токена
    if (token.header.version != Version.v2 ||
        token.header.purpose != Purpose.local) {
      throw FormatException('Token format is incorrect: not a v2.local token');
    }

    final payload = token.payloadLocal;
    if (payload == null) throw UnsupportedError('Invalid payload type.');
    final secretBox = payload.secretBox;
    final nonce = payload.nonce;
    if (nonce == null) {
      throw Exception('Missing nonce');
    }
    if (secretBox == null) {
      throw Exception('Missing secretBox');
    }

    // Получаем AAD для проверки целостности
    final aad = token.localAADPreAuthenticationEncoding;

    // В v2 используется XChaCha20-Poly1305 с nonce длиной 24 байта
    if (nonce.bytes.length != nonceLength) {
      throw FormatException(
          'Invalid nonce length for XChaCha20: expected 24 bytes');
    }

    // Используем класс XChaCha20Poly1305 для расшифровки
    final cipher = XChaCha20Poly1305();

    // Расшифровываем данные
    final decrypted = await cipher.decrypt(
      SecretBox(
        secretBox.cipherText
            .sublist(0, secretBox.cipherText.length - macLength),
        nonce: nonce.bytes,
        mac: MacWrapper(secretBox.cipherText
            .sublist(secretBox.cipherText.length - macLength)),
      ),
      aad: aad,
      secretKey: secretKey,
    );

    // Возвращаем расшифрованное сообщение
    return Package(
      content: decrypted,
      footer: token.footer,
    );
  }

  /// Шифрует данные и создает PASETO v2.local токен
  static Future<Payload> encrypt(
    Package package, {
    required SecretKey secretKey,
  }) async {
    // Инициализируем регистрацию алгоритмов
    PasetoRegistryInitializer.initV2Local();

    // Создаем экземпляр XChaCha20-Poly1305
    final cipher = XChaCha20Poly1305();

    // Генерируем случайный nonce
    final nonceBytes = await cipher.newNonce();
    final nonce = MacWrapper(nonceBytes.sublist(0, nonceLength));

    // Создаем токен с пустым шифротекстом для PAE (Pre-Authentication Encoding)
    final preAuth = Token.preAuthenticationEncoding(
      header: header,
      payload: PayloadLocal(
        secretBox: null,
        nonce: nonce,
      ),
      footer: package.footer,
    );

    // Шифруем данные
    final secretBox = await cipher.encrypt(
      package.content,
      nonce: nonceBytes,
      aad: preAuth,
      secretKey: secretKey,
    );

    // Объединяем шифротекст и MAC в одно поле
    final combinedCiphertext = secretBox.cipherText + secretBox.mac.bytes;

    // Создаем payload
    return PayloadLocal(
      nonce: nonce,
      secretBox: SecretBox(
        combinedCiphertext,
        nonce: nonceBytes,
        mac: secretBox.mac,
      ),
    );
  }
}

/// Обертка для Mac чтобы избежать конфликтов имен с PointyCastle
@immutable
class MacWrapper implements Mac {
  const MacWrapper(this._bytes);

  final List<int> _bytes;

  @override
  List<int> get bytes => _bytes;

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! Mac) return false;

    if (bytes.length != other.bytes.length) return false;

    for (var i = 0; i < bytes.length; i++) {
      if (bytes[i] != other.bytes[i]) return false;
    }

    return true;
  }

  @override
  int get hashCode => Object.hashAll(bytes);
}

/// Исключение для ошибок криптографии
class CryptographyException implements Exception {
  CryptographyException(this.message);
  final String message;

  @override
  String toString() => 'CryptographyException: $message';
}

/// Исключение возникающее при неправильном MAC
class SecretBoxAuthenticationError extends Error {
  SecretBoxAuthenticationError(this.message);
  final String message;

  @override
  String toString() => 'SecretBoxAuthenticationError: $message';
}
