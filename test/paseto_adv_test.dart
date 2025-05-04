import 'dart:convert';
import 'dart:typed_data';

import 'package:paseto_dart/paseto_dart.dart';
import 'package:paseto_dart/crypto/ed25519.dart' as ed25519_pkg;
import 'package:test/test.dart';

void main() {
  group('PASETO Advanced Tests', () {
    // Проверяем работу с implicit assertions в v3 и v4
    group('Implicit Assertions', () {
      test('v3.local с implicit assertions', () async {
        final secretKey =
            SecretKeyData(Uint8List.fromList(List.generate(32, (i) => i)));
        final payload = utf8
            .encode('{"data":"Тестовые данные","exp":"2023-01-01T00:00:00Z"}');

        // Данные для implicit assertion
        final context = utf8.encode('{"user_id": 42, "role": "admin"}');

        // Создаем пакет
        final package = Package(content: payload);

        // Шифруем с implicit assertions
        final encPayload = await LocalV3.encrypt(
          package,
          secretKey: secretKey,
          implicit: context,
        );

        final token = Token(
          header: LocalV3.header,
          payload: encPayload,
          footer: null,
        );

        final tokenString = token.toTokenString;

        // Пытаемся расшифровать без implicit assertions или с неправильными - должно быть исключение
        final tokenObj = await Token.fromString(tokenString);
        expect(
          () => tokenObj.decryptLocalMessage(
            secretKey: secretKey,
            // Без implicit assertion
          ),
          throwsA(isA<Exception>()),
        );

        expect(
          () => tokenObj.decryptLocalMessage(
            secretKey: secretKey,
            implicit: utf8.encode(
                '{"user_id": 99, "role": "user"}'), // Неправильный контекст
          ),
          throwsA(isA<Exception>()),
        );

        // Расшифровываем с правильным implicit assertion
        final decrypted = await tokenObj.decryptLocalMessage(
          secretKey: secretKey,
          implicit: context,
        );

        expect(utf8.decode(decrypted.package.content), utf8.decode(payload));
      });

      test('v4.public с implicit assertions', () async {
        // Генерируем ключевую пару
        final ed25519 = ed25519_pkg.Ed25519();
        final keyPair = await ed25519.newKeyPair();

        final payload = utf8
            .encode('{"data":"Тестовые данные","exp":"2023-01-01T00:00:00Z"}');

        // Данные для implicit assertion
        final context = utf8.encode('{"user_id": 42, "role": "admin"}');

        // Создаем пакет
        final package = Package(content: payload);

        // Подписываем с implicit assertions
        final signedPayload = await PublicV4.sign(
          package,
          secretKey: keyPair.privateKey,
          implicit: context,
        );

        final token = Token(
          header: PublicV4.header,
          payload: signedPayload,
          footer: null,
        );

        final tokenString = token.toTokenString;

        // Пытаемся проверить подпись без implicit assertions или с неправильными - должно быть исключение
        final tokenObj = await Token.fromString(tokenString);
        expect(
          () => tokenObj.verifyPublicMessage(
            publicKey: keyPair.publicKey,
            // Без implicit assertion
          ),
          throwsA(isA<Exception>()),
        );

        expect(
          () => tokenObj.verifyPublicMessage(
            publicKey: keyPair.publicKey,
            implicit: utf8.encode(
                '{"user_id": 99, "role": "user"}'), // Неправильный контекст
          ),
          throwsA(isA<Exception>()),
        );

        // Проверяем подпись с правильным implicit assertion
        final verified = await tokenObj.verifyPublicMessage(
          publicKey: keyPair.publicKey,
          implicit: context,
        );

        expect(utf8.decode(verified.package.content), utf8.decode(payload));
      });
    });

    // Тестируем работу с футерами
    group('Footer Tests', () {
      test('v4.local с футером', () async {
        final secretKey =
            SecretKeyData(Uint8List.fromList(List.generate(32, (i) => i)));
        final payload = utf8
            .encode('{"data":"Тестовые данные","exp":"2023-01-01T00:00:00Z"}');

        // Данные для футера
        final footer = utf8.encode('{"kid":"ключ-123"}');

        // Создаем пакет
        final package = Package(
          content: payload,
          footer: footer,
        );

        // Шифруем
        final encPayload = await LocalV4.encrypt(
          package,
          secretKey: secretKey,
        );

        final token = Token(
          header: LocalV4.header,
          payload: encPayload,
          footer: footer,
        );

        final tokenString = token.toTokenString;

        // Проверяем, что футер правильно сохраняется
        final parts = tokenString.split('.');
        expect(parts.length, 4); // header, payload, ciphertext, footer

        final decodedFooter = SafeBase64.decode(parts[3]);
        expect(utf8.decode(decodedFooter), utf8.decode(footer));

        // Расшифровываем токен и проверяем футер
        final tokenObj = await Token.fromString(tokenString);
        final decrypted = await tokenObj.decryptLocalMessage(
          secretKey: secretKey,
        );

        expect(utf8.decode(decrypted.package.content), utf8.decode(payload));
        expect(decrypted.package.footer, footer);
      });
    });

    // Тестируем специфические ошибки
    group('Error Handling', () {
      test('Неверный формат токена', () async {
        expect(
          () => Token.fromString('invalid.token.format'),
          throwsA(isA<FormatException>()),
        );
      });

      test('Неверная версия токена', () async {
        expect(
          () => Token.fromString('v9.local.invalidtoken'),
          throwsA(isA<FormatException>()),
        );
      });

      test('Неверный ключ шифрования', () async {
        final secretKey =
            SecretKeyData(Uint8List.fromList(List.generate(32, (i) => i)));
        final payload = utf8.encode('{"data":"test"}');

        // Создаем пакет
        final package = Package(content: payload);

        // Шифруем
        final encPayload = await LocalV4.encrypt(
          package,
          secretKey: secretKey,
        );

        final token = Token(
          header: LocalV4.header,
          payload: encPayload,
          footer: null,
        );

        final tokenString = token.toTokenString;
        final tokenObj = await Token.fromString(tokenString);

        // Пытаемся расшифровать с неверным ключом
        final wrongKey =
            SecretKeyData(Uint8List.fromList(List.generate(32, (i) => i + 1)));
        expect(
          () => tokenObj.decryptLocalMessage(
            secretKey: wrongKey,
          ),
          throwsA(isA<Exception>()),
        );
      });
    });
  });
}
