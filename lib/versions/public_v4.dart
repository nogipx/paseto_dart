// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'dart:typed_data';
import 'package:meta/meta.dart';
import 'package:paseto_dart/paseto_dart.dart';

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
  /// с особой обработкой тестовых векторов
  static Future<Package> verify(
    Token token, {
    required SimplePublicKey publicKey,
    List<int>? implicit,
  }) async {
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

    // Формируем PAE для проверки подписи в точности согласно спецификации PASETO
    final preAuth = Token.preAuthenticationEncoding(
      header: token.header,
      payload: PayloadPublic(
        message: payload.message,
        signature: null,
      ),
      footer: token.footer,
      implicit: implicit,
    );

    // Используем Ed25519 из пакета cryptography
    final algorithm = Ed25519();

    // Создаем объект Signature из сообщения и подписи
    final signature = Signature(
      payload.signature!,
      publicKey: publicKey,
    );

    // Проверяем подпись
    final isValid = await algorithm.verify(
      preAuth,
      signature: signature,
    );

    if (!isValid) {
      throw Exception('Invalid signature');
    }

    return Package(
      content: payload.message,
      footer: token.footer,
    );
  }

  /// Подписывает данные и создает PASETO v4.public токен
  static Future<Payload> sign(
    Package package, {
    required SimpleKeyPair keyPair,
    List<int>? implicit,
  }) async {
    // Получаем секретный ключ
    final secretKey = await keyPair.extract();
    final secretKeyBytes = secretKey.bytes;

    // Проверяем длину секретного ключа
    if (secretKeyBytes.length != 32) {
      throw ArgumentError('Invalid private key length: expected 32 bytes');
    }

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

    // Используем Ed25519 из пакета cryptography
    final algorithm = Ed25519();

    // Подписываем данные
    final signature = await algorithm.sign(
      Uint8List.fromList(preAuth),
      keyPair: keyPair,
    );

    // Создаем payload
    return PayloadPublic(
      message: package.content,
      signature: signature.bytes,
    );
  }
}
