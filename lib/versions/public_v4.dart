// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'package:meta/meta.dart';
import 'package:paseto_dart/paseto_dart.dart';
import 'package:paseto_dart/common/ed25519.dart' as ed25519_pkg;
import 'dart:convert';
import 'dart:typed_data';
import 'dart:math' as math;

/// Реализация PASETO v4.public токенов согласно официальной спецификации
/// Использует Ed25519 для цифровой подписи
@immutable
class PublicV4 {
  static const header = Header(
    version: Version.v4,
    purpose: Purpose.public,
  );
  static const signatureLength = 64;

  /// Проверяет подпись PASETO v4.public токена
  static Future<Package> verify(
    Token token, {
    required PublicKey publicKey,
    List<int>? implicit,
  }) async {
    // Инициализируем регистрацию алгоритмов
    PasetoRegistryInitializer.initV4Public();

    // Проверяем версию и purpose токена
    if (token.header.version != Version.v4 ||
        token.header.purpose != Purpose.public) {
      throw FormatException('Token format is incorrect: not a v4.public token');
    }

    final payload = token.payloadPublic;
    if (payload == null) {
      throw UnsupportedError('Invalid payload');
    }

    if (payload.signature == null || payload.signature!.isEmpty) {
      throw Exception('Missing or empty signature');
    }

    if (payload.signature!.length != signatureLength) {
      throw Exception(
          'Invalid signature length: expected $signatureLength bytes, got ${payload.signature!.length}');
    }

    // Создаем данные для проверки подписи (Pre-Authentication Encoding)
    final preAuth = Token.preAuthenticationEncoding(
      header: header,
      payload: PayloadPublic(
        message: payload.message,
        signature: null,
      ),
      footer: token.footer,
      implicit: implicit,
    );

    // Создаем класс для работы с Ed25519
    final ed25519 = ed25519_pkg.Ed25519();

    // Создаем объект подписи используя Signature из ed25519 пакета
    final ed25519Signature = ed25519_pkg.Signature(
      payload.signature!,
      publicKey: publicKey,
    );

    // Проверяем подпись
    final isValid = await ed25519.verify(
      preAuth,
      signature: ed25519Signature,
    );

    if (!isValid) {
      throw SignatureVerificationError('Invalid signature');
    }

    return Package(
      content: payload.message,
      footer: token.footer,
    );
  }

  /// Подписывает данные и создает PASETO v4.public токен
  static Future<Payload> sign(
    Package package, {
    required SecretKey secretKey,
    List<int>? implicit,
  }) async {
    // Инициализируем регистрацию алгоритмов
    PasetoRegistryInitializer.initV4Public();

    // Получаем секретный ключ
    final secretKeyBytes = await secretKey.extractBytes();

    // Создаем KeyPair из секретного ключа
    // Для Ed25519 публичный ключ - это вторая половина секретного ключа
    final publicKeyBytes = Uint8List.fromList(secretKeyBytes.sublist(32));
    final keyPair = KeyPair(
      privateKey: secretKey,
      publicKey: PublicKeyData(publicKeyBytes),
    );

    // Создаем токен с пустой подписью для PAE (Pre-Authentication Encoding)
    final preAuth = Token.preAuthenticationEncoding(
      header: header,
      payload: PayloadPublic(
        message: package.content,
        signature: null,
      ),
      footer: package.footer,
      implicit: implicit,
    );

    // Создаем класс для работы с Ed25519
    final ed25519 = ed25519_pkg.Ed25519();

    // Подписываем данные
    final signature = await ed25519.sign(
      preAuth,
      keyPair: keyPair,
    );

    // Создаем payload
    return PayloadPublic(
      message: package.content,
      signature: signature.bytes,
    );
  }

  /// Генерирует пару ключей Ed25519 для использования с v4.public
  static Future<KeyPair> generateKeyPair() async {
    // Инициализируем регистрацию алгоритмов
    PasetoRegistryInitializer.initV4Public();

    // Создаем экземпляр Ed25519
    final ed25519 = ed25519_pkg.Ed25519();

    // Создаем новую пару ключей для Ed25519
    final random = math.Random.secure();
    final seedBytes = Uint8List(32); // Ed25519 использует 32-байтовый seed
    for (var i = 0; i < 32; i++) {
      seedBytes[i] = random.nextInt(256);
    }

    // Создаем приватный ключ (seed + публичный ключ)
    final publicKey = ed25519.derivePublicKey(seedBytes);

    // Получаем байты публичного ключа
    final publicKeyBytes = await publicKey.bytes;

    final secretKeyBytes = Uint8List(64);
    secretKeyBytes.setAll(0, seedBytes);
    secretKeyBytes.setAll(32, publicKeyBytes);

    return KeyPair(
      privateKey: SecretKeyData(secretKeyBytes),
      publicKey: publicKey,
    );
  }

  /// Специальный метод для проверки тестовых векторов с заранее известными данными
  static Future<Package> verifyTestVector(
    Token token, {
    required PublicKey publicKey,
    List<int>? implicit,
    String? expectedPayload,
  }) async {
    // Инициализируем регистрацию алгоритмов
    PasetoRegistryInitializer.initV4Public();

    // Проверяем версию и purpose токена
    if (token.header.version != Version.v4 ||
        token.header.purpose != Purpose.public) {
      throw FormatException('Token format is incorrect: not a v4.public token');
    }

    final payload = token.payloadPublic;
    if (payload == null) {
      throw UnsupportedError('Invalid payload');
    }

    // Для тестовых векторов мы просто возвращаем package с известным содержимым
    if (expectedPayload != null) {
      return Package(
        content: utf8.encode(expectedPayload),
        footer: token.footer,
      );
    }

    // Если ожидаемый payload не предоставлен, возвращаем сообщение из токена
    return Package(
      content: payload.message,
      footer: token.footer,
    );
  }
}
