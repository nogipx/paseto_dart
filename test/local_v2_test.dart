import 'dart:convert';

import 'package:test/test.dart';
import 'package:paseto_dart/paseto_dart.dart';
import 'test_helpers.dart';

void main() {
  late SecretKey secretKey;

  setUp(() async {
    // Создаем предсказуемый секретный ключ для тестов
    secretKey = await TestHelpers.generateSecretKey(32);
  });

  test('шифрование и расшифровка', () async {
    const plaintext = 'Это тестовое сообщение для PASETO v2.local';

    // Шифруем сообщение
    final message = await Message.encryptString(
      plaintext,
      version: Version.v2,
      secretKey: secretKey,
    );

    // Проверяем заголовок
    expect(message.header.version, equals(Version.v2));
    expect(message.header.purpose, equals(Purpose.local));

    // Проверяем токен
    final token = message.toToken;
    expect(token.toTokenString.startsWith('v2.local.'), isTrue);

    // Расшифровываем
    final decryptedMessage = await token.decryptLocalMessage(
      secretKey: secretKey,
    );

    // Проверяем результат
    expect(decryptedMessage.stringContent, equals(plaintext));
  });

  test('шифрование и расшифровка с футером', () async {
    const plaintext = 'Сообщение с футером';
    const footer = 'Тестовый футер';

    // Создаем пакет с футером
    final package = TestHelpers.createTextPackage(plaintext, footer: footer);

    // Шифруем через LocalV2 напрямую
    final payload = await LocalV2.encrypt(
      package,
      secretKey: secretKey,
    );

    final token = Token(
      header: LocalV2.header,
      payload: payload,
      footer: package.footer,
    );

    // Токен должен иметь 4 части с футером
    final tokenString = token.toTokenString;
    final parts = tokenString.split('.');
    expect(parts.length, equals(4));

    // Расшифровываем
    final decrypted = await LocalV2.decrypt(
      token,
      secretKey: secretKey,
    );

    // Проверяем результат
    expect(utf8.decode(decrypted.content), equals(plaintext));
    expect(utf8.decode(decrypted.footer!), equals(footer));
  });

  test('неверный ключ вызывает ошибку', () async {
    // Создаем новое сообщение для тестирования
    const plaintext = 'PASETO с неверным ключом должен вызвать ошибку';

    // Создаем сообщение и шифруем его
    final message = await Message.encryptString(
      plaintext,
      version: Version.v2,
      secretKey: secretKey,
    );

    final token = message.toToken;

    // Создаем второй ключ той же длины, но с другими данными
    final anotherKey = await TestHelpers.generateSecretKey(32);

    // Расшифровка с правильным ключом должна работать
    final decryptedMessage = await token.decryptLocalMessage(
      secretKey: secretKey,
    );
    expect(decryptedMessage.stringContent, equals(plaintext));

    // Расшифровка с неправильным ключом должна вызвать ошибку
    bool errorThrown = false;
    try {
      await token.decryptLocalMessage(secretKey: anotherKey);
      fail('Расшифровка с неправильным ключом должна была вызвать ошибку');
    } catch (e) {
      // Любая ошибка здесь означает успех теста
      errorThrown = true;
    }

    expect(errorThrown, isTrue,
        reason: 'Ожидалась ошибка при расшифровке с неправильным ключом');
  });
}
