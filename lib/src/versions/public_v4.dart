// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
// SPDX-FileCopyrightText: 2026 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: MIT

import 'dart:convert';
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

    // Важно: для v4 используем пустой массив, если implicit не задан
    final implicitBytes = implicit ?? [];

    // Проверяем, что публичный ключ имеет правильный тип KeyPairType.ed25519
    if (publicKey.type != KeyPairType.ed25519) {
      throw ArgumentError('Public key must be of type KeyPairType.ed25519');
    }

    // Проверяем, что публичный ключ имеет правильную длину (32 байта)
    if (publicKey.bytes.length != 32) {
      throw ArgumentError('Public key must be 32 bytes');
    }

    // Формируем PAE для проверки подписи в точности согласно спецификации PASETO
    final headerString = token.header.toTokenString;
    final headerBytes = Uint8List.fromList(utf8.encode(headerString));

    // Собираем компоненты PAE (Pre-Authentication Encoding)
    final preAuth = _preAuthenticationEncoding(
      headerBytes: headerBytes,
      message: payload.message,
      footer: token.footer ?? [],
      implicit: implicitBytes,
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

    // Важно: для v4 используем пустой массив, если implicit не задан
    final implicitBytes = implicit ?? [];

    // Формируем PAE для подписи в точности согласно спецификации PASETO
    final headerString = "v4.public.";
    final headerBytes = Uint8List.fromList(utf8.encode(headerString));

    // Собираем компоненты PAE (Pre-Authentication Encoding)
    final preAuth = _preAuthenticationEncoding(
      headerBytes: headerBytes,
      message: package.content,
      footer: package.footer ?? [],
      implicit: implicitBytes,
    );

    // Используем Ed25519 из пакета cryptography
    final algorithm = Ed25519();

    // Подписываем данные
    final signature = await algorithm.sign(
      preAuth,
      keyPair: keyPair,
    );

    // Создаем payload
    return PayloadPublic(
      message: package.content,
      signature: signature.bytes,
    );
  }

  /// Реализация PAE (Pre-Authentication Encoding) для v4.public согласно спецификации
  static Uint8List _preAuthenticationEncoding({
    required Uint8List headerBytes,
    required List<int> message,
    required List<int> footer,
    required List<int> implicit,
  }) {
    // Реализуем PAE согласно спецификации PASETO
    final result = <int>[];

    // Количество компонентов в PAE (4 - header, message, footer, implicit assertions)
    final componentCount = 4;

    // Запись количества компонентов (8 байт, little-endian)
    result.addAll(_int64LE(componentCount));

    // Запись длины header (8 байт, little-endian) и самого header
    result.addAll(_int64LE(headerBytes.length));
    result.addAll(headerBytes);

    // Запись длины message (8 байт, little-endian) и самого message
    result.addAll(_int64LE(message.length));
    result.addAll(message);

    // Запись длины footer (8 байт, little-endian) и самого footer
    result.addAll(_int64LE(footer.length));
    result.addAll(footer);

    // Запись длины implicit assertions (8 байт, little-endian) и самих implicit assertions
    result.addAll(_int64LE(implicit.length));
    result.addAll(implicit);

    return Uint8List.fromList(result);
  }

  /// Преобразует 64-битное целое число в массив байт в формате little-endian
  static List<int> _int64LE(int value) {
    final bytes = Uint8List(8);
    for (var i = 0; i < 8; i++) {
      bytes[i] = (value >> (i * 8)) & 0xFF;
    }
    // Последний байт должен иметь MSB=0 (для 64-bit целых чисел)
    bytes[7] &= 0x7F;
    return bytes;
  }
}
