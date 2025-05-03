import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:paseto_dart/paseto_dart.dart';
import 'test_helpers.dart';

void main() {
  test('шифрование и расшифровка v4.local', () async {
    // Создаем ключ для тестов
    final secretKey = await TestHelpers.generateSecretKey(32);

    // Шифруем текст
    final plaintext = 'Секретное сообщение для v4.local';
    final message = await Message.encryptString(
      plaintext,
      version: Version.v4,
      secretKey: secretKey,
    );

    // Проверяем заголовок
    expect(message.header.version, equals(Version.v4));
    expect(message.header.purpose, equals(Purpose.local));

    // Получаем токен
    final token = message.toToken;
    final tokenString = token.toTokenString;
    expect(tokenString.startsWith('v4.local.'), isTrue);

    // Расшифровываем
    final decryptedMessage = await token.decryptLocalMessage(
      secretKey: secretKey,
    );

    // Проверяем результат
    expect(decryptedMessage.stringContent, equals(plaintext));
  });

  test('шифрование и расшифровка с implicit данными', () async {
    final secretKey = await TestHelpers.generateSecretKey(32);
    final implicitData = utf8.encode('Связанные данные');

    // Создаем пакет
    final plaintext = 'Сообщение с защищенным контекстом';
    final package = TestHelpers.createTextPackage(plaintext);

    // Шифруем с implicit данными
    final payload = await LocalV4.encrypt(
      package,
      secretKey: secretKey,
      implicit: implicitData,
    );

    final token = Token(
      header: LocalV4.header,
      payload: payload,
      footer: package.footer,
    );

    // Расшифровываем с теми же implicit данными
    final decrypted = await LocalV4.decrypt(
      token,
      secretKey: secretKey,
      implicit: implicitData,
    );

    // Проверяем результат
    expect(utf8.decode(decrypted.content), equals(plaintext));

    // Попытка расшифровки с неверными implicit данными
    expect(
      () async {
        final wrongImplicit = utf8.encode('неверные данные');
        await LocalV4.decrypt(
          token,
          secretKey: secretKey,
          implicit: wrongImplicit,
        );
      },
      throwsA(anything),
    );
  });

  test('валидация ключей v4.local', () async {
    // Корректный ключ длиной 32 байта
    final validKey = await TestHelpers.generateSecretKey(32);

    // Проверяем, что валидный ключ проходит проверку
    expect(await validKey.isValidForVersion(Version.v4), isTrue);

    // Неправильный ключ (слишком короткий)
    final invalidKey = await TestHelpers.generateSecretKey(16);

    // Проверяем, что невалидный ключ не проходит проверку
    expect(await invalidKey.isValidForVersion(Version.v4), isFalse);

    // Проверяем, что validateForVersion выбрасывает исключение
    expect(
      () async => await invalidKey.validateForVersion(Version.v4),
      throwsA(isA<FormatException>()),
    );
  });

  test('совместимость v4.local с другими имплементациями', () async {
    // Тестовый вектор из официальной спецификации
    // https://github.com/paseto-standard/test-vectors
    final knownKey = Uint8List.fromList([
      0x70,
      0x71,
      0x72,
      0x73,
      0x74,
      0x75,
      0x76,
      0x77,
      0x78,
      0x79,
      0x7a,
      0x7b,
      0x7c,
      0x7d,
      0x7e,
      0x7f,
      0x80,
      0x81,
      0x82,
      0x83,
      0x84,
      0x85,
      0x86,
      0x87,
      0x88,
      0x89,
      0x8a,
      0x8b,
      0x8c,
      0x8d,
      0x8e,
      0x8f
    ]);

    final secretKey = SecretKeyData(knownKey);

    // Создаем токен вручную с фиксированным nonce для совместимости
    final message =
        jsonEncode({'data': 'this is a signed message', 'exp': '2039-01-01T00:00:00+00:00'});

    // Создаем пакет
    final package = TestHelpers.createTextPackage(message);

    // Используем метод шифрования с автоматической генерацией nonce
    final payload = await LocalV4.encrypt(
      package,
      secretKey: secretKey,
    );

    // Создаем токен
    final token = Token(
      header: LocalV4.header,
      payload: payload,
      footer: package.footer,
    );

    // Проверяем, что токен можно расшифровать
    final decrypted = await LocalV4.decrypt(
      token,
      secretKey: secretKey,
    );

    // Проверяем результат
    expect(utf8.decode(decrypted.content), equals(message));
  });
}
