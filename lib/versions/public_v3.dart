// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'package:meta/meta.dart';
import 'package:paseto_dart/paseto_dart.dart';

/// Реализация PASETO v3.public токенов согласно официальной спецификации
/// Использует ECDSA P-384 с SHA-384
@immutable
class PublicV3 {
  static const header = Header(
    version: Version.v3,
    purpose: Purpose.public,
  );
  static const signatureLength = 96; // Для ECDSA P-384 с SHA-384

  /// Проверяет подпись PASETO v3.public токена
  static Future<Package> verify(
    Token token, {
    required PublicKey publicKey,
    List<int>? implicit,
  }) async {
    final payload = token.payloadPublic;
    if (payload == null) {
      throw UnsupportedError('Invalid payload');
    }

    if (payload.signature == null || payload.signature!.isEmpty) {
      throw Exception('Missing or empty signature');
    }

    // P-384 использует ECDSA с SHA-384
    final algorithm = Ecdsa.p384(Sha384());

    // Создаем данные для проверки подписи (PAE encoding)
    final dataToVerify = token.standardPreAuthenticationEncoding;

    // Выполняем проверку подписи
    final isValid = await algorithm.verify(
      dataToVerify,
      signature: Signature(
        payload.signature!,
        publicKey: publicKey,
      ),
    );

    if (!isValid) {
      throw SignatureVerificationError(
          'Invalid signature: message has been tampered with or was signed with a different key');
    }

    return Package(
      content: payload.message,
      footer: token.footer,
    );
  }

  /// Подписывает данные и создает PASETO v3.public токен
  static Future<Payload> sign(
    Package package, {
    required KeyPair keyPair,
    List<int>? implicit,
  }) async {
    // В PASETO v3 используется ECDSA P-384 с SHA-384
    final algorithm = Ecdsa.p384(Sha384());

    // Подготавливаем данные для подписи
    final dataToSign = Token.preAuthenticationEncoding(
      header: PublicV3.header,
      payload: PayloadPublic(message: package.content),
      footer: package.footer,
      implicit: implicit ?? [],
    );

    // Подписываем данные
    final signature = await algorithm.sign(
      dataToSign,
      keyPair: keyPair,
    );

    return PayloadPublic(
      message: package.content,
      signature: signature.bytes,
    );
  }
}

/// Ошибка при проверке подписи в PASETO токене
class SignatureVerificationError implements Exception {
  const SignatureVerificationError(this.message);
  final String message;

  @override
  String toString() => 'SignatureVerificationError: $message';
}

/// Исключение для ошибок криптографии
class CryptographyException implements Exception {
  CryptographyException(this.message);
  final String message;

  @override
  String toString() => 'CryptographyException: $message';
}
