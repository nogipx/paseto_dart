import 'dart:convert';

import 'package:test/test.dart';
import 'package:paseto_dart/paseto_dart.dart';
import 'package:paseto_dart/versions/local_v3.dart' as v3;
import 'test_helpers.dart';

void main() {
  group('LocalV3', () {
    // В этом тесте мы проверяем полный цикл шифрования-расшифрования данных
    test('полный цикл шифрования-расшифрования', () async {
      // Создаем новый ключ шифрования каждый раз
      // чтобы избежать зависимости между тестами
      final secretKey = await TestHelpers.generateSecretKey(32);

      // Сначала шифруем данные
      final plaintext = 'Секретное сообщение для PASETO v3';
      final encryptedMessage = await Message.encryptString(
        plaintext,
        version: Version.v3,
        secretKey: secretKey,
      );

      // Проверяем, что заголовок корректный
      expect(encryptedMessage.header.version, equals(Version.v3));
      expect(encryptedMessage.header.purpose, equals(Purpose.local));

      // Проверяем, что nonce и MAC присутствуют с правильными длинами
      final token = encryptedMessage.toToken;
      final payload = token.payloadLocal;
      expect(payload!.nonce!.bytes.length, equals(LocalV3.nonceLength));

      final cipherText = payload.secretBox!.cipherText;
      expect(cipherText.length > LocalV3.macLength, isTrue);

      // Токен должен начинаться с v3.local.
      expect(token.toTokenString.startsWith('v3.local.'), isTrue);

      // Преобразуем в токен и обратно расшифровываем
      final decryptedMessage = await token.decryptLocalMessage(
        secretKey: secretKey,
      );

      // Проверяем, что исходный текст совпадает с расшифрованным
      expect(decryptedMessage.stringContent, equals(plaintext));
    });

    // В этом тесте проверяем, что неверный ключ вызывает ошибку
    test('неверный ключ вызывает ошибку', () async {
      // Используем предсказуемые данные
      const tokenString =
          'v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADbfcIURX_0pVZVU1mAESUzrKZAsRm2EsD6yBoZYn4tQVs5HAa2yvkfwNKXQjJUE5MJ_6QPMg';
      final token = await Token.fromString(tokenString);

      // Предсказуемый ключ
      const hexKey =
          '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f';
      final correctKey = TestHelpers.secretKeyFromHexString(hexKey);

      // Изменяем последний байт ключа - это должно вызвать ошибку
      final wrongKeyBytes = List<int>.from(await correctKey.extractBytes());
      wrongKeyBytes[wrongKeyBytes.length - 1] = 0xFF; // Заменяем последний байт
      final wrongKey = SecretKeyData(wrongKeyBytes);

      // Попытка расшифровки неверным ключом должна вызвать ошибку
      await expectLater(
        () => token.decryptLocalMessage(secretKey: wrongKey),
        throwsA(isA<v3.SecretBoxAuthenticationError>()),
      );
    });

    // Проверяем, что подделка данных обнаруживается
    test('обнаружение подделки MAC', () async {
      final secretKey = await TestHelpers.generateSecretKey(32);

      // Шифруем данные
      final plaintext = 'Это сообщение будет подделано';
      final encryptedMessage = await Message.encryptString(
        plaintext,
        version: Version.v3,
        secretKey: secretKey,
      );

      // Получаем токен и извлекаем payload
      final token = encryptedMessage.toToken;
      final originalTokenString = token.toTokenString;

      // Подделываем последний байт шифротекста
      final parts = originalTokenString.split('.');
      expect(parts.length, greaterThanOrEqualTo(3));

      final originalPayload = parts[2];
      final bytes = decodePasetoBase64(originalPayload);

      // Изменяем байт в середине шифротекста (не MAC)
      bytes[bytes.length ~/ 2] = (bytes[bytes.length ~/ 2] + 1) % 256;

      // Создаем новый подделанный токен
      final tamperedPayload = encodePasetoBase64(bytes);
      var tamperedTokenString = '${parts[0]}.${parts[1]}.$tamperedPayload';
      if (parts.length > 3) {
        tamperedTokenString = '$tamperedTokenString.${parts[3]}';
      }

      // Проверяем, что подделка обнаруживается
      expect(
        () async {
          final tamperedToken = await Token.fromString(tamperedTokenString);
          await tamperedToken.decryptLocalMessage(secretKey: secretKey);
        },
        throwsA(anyOf(isA<CryptographyException>(),
            isA<v3.SecretBoxAuthenticationError>())),
      );
    });

    // Проверяем работу с JSON данными
    test('шифрование и расшифрование JSON данных', () async {
      final secretKey = await TestHelpers.generateSecretKey(32);

      // Создаем JSON данные
      final jsonData = {
        'data': 'Важные данные',
        'exp': '2023-12-31T23:59:59Z',
        'sub': 'test-user',
        'iat': '2023-01-01T00:00:00Z',
      };
      final jsonString = jsonEncode(jsonData);

      // Шифруем JSON
      final encryptedMessage = await Message.encryptString(
        jsonString,
        version: Version.v3,
        secretKey: secretKey,
      );

      // Расшифровываем
      final token = encryptedMessage.toToken;
      final decryptedMessage = await token.decryptLocalMessage(
        secretKey: secretKey,
      );

      // Проверяем данные
      expect(decryptedMessage.stringContent, equals(jsonString));
      expect(decryptedMessage.jsonContent, equals(jsonData));
    });

    // Проверяем работу с футером
    test('шифрование и расшифрование с футером', () async {
      final secretKey = await TestHelpers.generateSecretKey(32);

      // Данные для шифрования
      final plaintext = 'Сообщение с футером';
      final footer = 'Информация о ключе v3';

      // Шифруем с футером
      final package = Package(
        content: utf8.encode(plaintext),
        footer: utf8.encode(footer),
      );

      final payload = await LocalV3.encrypt(package, secretKey: secretKey);
      final token = Token(
        header: LocalV3.header,
        payload: payload,
        footer: package.footer,
      );

      // Токен должен содержать 4 части с футером
      final tokenString = token.toTokenString;
      final parts = tokenString.split('.');
      expect(parts.length, equals(4));

      // Последняя часть должна быть футером в base64url
      final decodedFooter = utf8.decode(decodePasetoBase64(parts[3]));
      expect(decodedFooter, equals(footer));

      // Расшифровываем и проверяем, что футер сохранился
      final decrypted = await LocalV3.decrypt(token, secretKey: secretKey);
      final decodedContent = utf8.decode(decrypted.content);

      // Корректно обрабатываем потенциально пустой footer
      final footerBytes = decrypted.footer;
      final decodedFooterContent = footerBytes != null && footerBytes.isNotEmpty
          ? utf8.decode(footerBytes)
          : '';

      expect(decodedContent, equals(plaintext));
      expect(decodedFooterContent, equals(footer));
    });

    // Проверяем работу с implicit данными
    test('шифрование и расшифрование с implicit данными', () async {
      final secretKey = await TestHelpers.generateSecretKey(32);
      final implicitData =
          utf8.encode('дополнительные данные не включаемые в токен');

      // Данные для шифрования
      final plaintext = 'Сообщение с implicit данными';

      // Создаем package
      final package = Package(
        content: utf8.encode(plaintext),
      );

      // Шифруем с implicit данными
      final payload = await LocalV3.encrypt(
        package,
        secretKey: secretKey,
        implicit: implicitData,
      );

      final token = Token(
        header: LocalV3.header,
        payload: payload,
        footer: package.footer,
      );

      // Расшифровываем с теми же implicit данными
      final decrypted = await LocalV3.decrypt(
        token,
        secretKey: secretKey,
        implicit: implicitData,
      );

      // Проверяем результат
      final decodedContent = utf8.decode(decrypted.content);
      expect(decodedContent, equals(plaintext));

      // Попытка расшифровки без implicit данных должна вызвать ошибку
      expect(
        () async {
          await LocalV3.decrypt(
            token,
            secretKey: secretKey,
          );
        },
        throwsA(anyOf(isA<CryptographyException>(),
            isA<v3.SecretBoxAuthenticationError>())),
      );

      // Попытка расшифровки с другими implicit данными должна вызвать ошибку
      expect(
        () async {
          final wrongImplicit = utf8.encode('неверные данные');
          await LocalV3.decrypt(
            token,
            secretKey: secretKey,
            implicit: wrongImplicit,
          );
        },
        throwsA(anyOf(isA<CryptographyException>(),
            isA<v3.SecretBoxAuthenticationError>())),
      );
    });
  });
}

/// Декодирует строку из PASETO base64url-формата
List<int> decodePasetoBase64(String input) {
  // Заменяем URL-safe символы на стандартные base64
  String base64 = input.replaceAll('-', '+').replaceAll('_', '/');

  // Дополняем строку символами '=' если нужно до кратности 4
  while (base64.length % 4 != 0) {
    base64 += '=';
  }

  return base64Decode(base64);
}

/// Кодирует байты в PASETO base64url-формат
String encodePasetoBase64(List<int> bytes) {
  String base64 = base64Encode(bytes);

  // Заменяем стандартные base64 символы на URL-safe
  return base64.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}
