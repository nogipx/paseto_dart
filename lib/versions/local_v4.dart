// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'dart:convert';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:meta/meta.dart';
import 'package:paseto_dart/paseto_dart.dart';

/// Реализация PASETO v4.local для шифрования и расшифрования токенов
@immutable
class LocalV4 {
  /// Константы для v4.local
  static const nonceLength = 32; // Случайный nonce размер в байтах
  static const macLength = 32; // BLAKE2b-MAC размер в байтах
  static const encKeyLength = 32; // XChaCha20 ключ шифрования размер в байтах
  static const encKeyInfo =
      'paseto-encryption-key'; // Информация для ключа шифрования
  static const authKeyInfo =
      'paseto-auth-key-for-aead'; // Информация для ключа аутентификации

  /// Заголовок для v4.local
  static const header = Header(
    version: Version.v4,
    purpose: Purpose.local,
  );

  /// Расшифровывает PASETO v4.local токен и проверяет его целостность
  static Future<Package> decrypt(
    Token token, {
    required SecretKey secretKey,
    List<int>? implicit,
  }) async {
    // Проверка версии и purpose токена
    if (token.header.version != Version.v4 ||
        token.header.purpose != Purpose.local) {
      throw FormatException('Token format is incorrect: not a v4.local token');
    }

    final payload = token.payloadLocal;
    if (payload == null) throw UnsupportedError('Invalid payload type.');

    // Получаем nonce и ciphertext из payload
    final nonce = payload.nonce!.bytes;
    final secretBoxData = payload.secretBox!.cipherText;

    // Получаем ключевой материал
    final secretKeyBytes = await secretKey.extractBytes();
    if (secretKeyBytes.length < 32) {
      throw FormatException('Secret key must be at least 32 bytes');
    }

    // Используем установленные implicit или пустой массив
    final implicitBytes = implicit ?? [];

    // Выводим ключи для расшифровки и аутентификации
    final derivedKeys =
        await _deriveKeys(secretKeyBytes, nonce, implicit: implicitBytes);
    final encryptionKey = derivedKeys.encKey;
    final nonce2 = derivedKeys.nonce2;

    // Разделяем секретный блок на зашифрованный текст и MAC
    final macBytes = secretBoxData.sublist(secretBoxData.length - macLength);
    final cipherText =
        secretBoxData.sublist(0, secretBoxData.length - macLength);

    // Собираем preAuth как в спецификации:
    // Pack h, n, c, f, and i together (in that order) using PAE
    final footer = token.footer ?? [];
    final preAuth = _preAuthenticationEncoding([
      utf8.encode("v4.local."),
      nonce,
      cipherText,
      footer,
      implicitBytes,
    ]);

    // Вычисляем ожидаемый MAC для проверки аутентичности
    // t = crypto_generichash(message = preAuth, key = Ak, length = 32);
    final computedMacHash =
        await Blake2b(hashLengthInBytes: macLength).hash(preAuth);
    final computedMac = computedMacHash.bytes;

    // Проверяем совпадение MAC
    if (!_constantTimeEquals(macBytes, computedMac)) {
      throw Exception('Authentication failed: MAC verification failed');
    }

    // Расшифровываем данные с использованием XChaCha20
    // Используем SimpleStreamCipher как замену XChaCha20
    final clearBytes = await _decryptXChaCha20(
      cipherText: cipherText,
      key: encryptionKey,
      nonce: nonce2,
    );

    // Возвращаем расшифрованный контент и footer
    return Package(content: clearBytes, footer: footer);
  }

  /// Шифрует данные и создает PASETO v4.local токен
  static Future<Payload> encrypt(
    Package package, {
    required SecretKey secretKey,
    List<int>? implicit,
  }) async {
    // Получаем ключевой материал
    final secretKeyBytes = await secretKey.extractBytes();
    if (secretKeyBytes.length < 32) {
      throw FormatException('Secret key must be at least 32 bytes');
    }

    // Генерируем случайный nonce длиной 32 байта для v4
    final random = math.Random.secure();
    final nonce = List<int>.generate(nonceLength, (_) => random.nextInt(256));

    // Используем установленные implicit или пустой массив
    final implicitBytes = implicit ?? [];

    // Выводим ключи для шифрования и аутентификации
    final derivedKeys =
        await _deriveKeys(secretKeyBytes, nonce, implicit: implicitBytes);
    final encryptionKey = derivedKeys.encKey;
    final authKey = derivedKeys.authKey;
    final nonce2 = derivedKeys.nonce2;

    // Шифруем с использованием XChaCha20
    // c = crypto_stream_xchacha20_xor(message = m, nonce = n2, key = Ek);
    final cipherText = await _encryptXChaCha20(
      clearText: package.content,
      key: encryptionKey,
      nonce: nonce2,
    );

    // Собираем preAuth согласно спецификации
    final footer = package.footer ?? [];
    final preAuth = _preAuthenticationEncoding([
      utf8.encode("v4.local."),
      nonce,
      cipherText,
      footer,
      implicitBytes,
    ]);

    // Вычисляем MAC для аутентификации
    // t = crypto_generichash(message = preAuth, key = Ak, length = 32);
    final macHash = await Blake2b(hashLengthInBytes: macLength).hash(preAuth);
    final mac = macHash.bytes;

    // Объединяем зашифрованный текст и MAC
    final combinedCipherText = [...cipherText, ...mac];

    // Возвращаем PASETO v4.local payload
    return PayloadLocal(
      nonce: Mac(nonce),
      secretBox: SecretBox(
        combinedCipherText,
        nonce: nonce,
        mac: Mac(mac),
      ),
    );
  }
}
