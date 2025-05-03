import 'package:meta/meta.dart';
import 'package:paseto_dart/paseto_dart.dart';
import 'package:paseto_dart/common/ed25519.dart' as ed25519_pkg;

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

    final payload = token.payloadPublic;
    if (payload == null) {
      throw UnsupportedError('Invalid payload');
    }

    if (payload.signature == null || payload.signature!.isEmpty) {
      throw Exception('Missing or empty signature');
    }

    if (payload.signature!.length != signatureLength) {
      throw Exception('Invalid signature length');
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
    required KeyPair keyPair,
    List<int>? implicit,
  }) async {
    // Инициализируем регистрацию алгоритмов
    PasetoRegistryInitializer.initV4Public();

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
}
