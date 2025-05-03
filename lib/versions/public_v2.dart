import 'package:meta/meta.dart';
import 'package:paseto_dart/paseto_dart.dart';

@immutable
class PublicV2 {
  static const header = Header(
    version: Version.v2,
    purpose: Purpose.public,
  );
  static const signatureLength = 64;

  static Future<Package> verify(
    Token token, {
    required PublicKey publicKey,
  }) async {
    // Инициализируем регистрацию алгоритмов
    PasetoRegistryInitializer.initV2Public();

    final payload = token.payloadPublic;
    if (payload == null) {
      throw UnsupportedError('Invalid payload');
    }

    // Используем класс Ed25519 для проверки подписи
    final ed25519 = Ed25519();

    // Создаем объект подписи
    final signature = Signature(
      payload.signature!,
      publicKey: publicKey,
    );

    // Проверяем подпись с использованием Ed25519
    final isValid = await ed25519.verify(
      token.standardPreAuthenticationEncoding,
      signature: signature,
    );

    if (!isValid) {
      throw SignatureVerificationError('Invalid signature');
    }

    return Package(
      content: payload.message,
      footer: token.footer,
    );
  }

  static Future<Payload> sign(
    Package package, {
    required KeyPair keyPair,
  }) async {
    // Инициализируем регистрацию алгоритмов
    PasetoRegistryInitializer.initV2Public();

    // Получаем преаутентификационное кодирование
    final preAuthenticationEncoding = Token.preAuthenticationEncoding(
      header: PublicV2.header,
      payload: PayloadPublic(message: package.content),
      footer: package.footer,
    );

    // Используем класс Ed25519 для подписи
    final ed25519 = Ed25519();

    // Подписываем сообщение
    final signature = await ed25519.sign(
      preAuthenticationEncoding,
      keyPair: keyPair,
    );

    return PayloadPublic(
      message: package.content,
      signature: signature.bytes,
    );
  }
}
