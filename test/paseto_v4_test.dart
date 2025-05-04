import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:paseto_dart/paseto_dart.dart';
import 'package:test/test.dart';

import 'test_utils.dart';
import 'test_vectors.dart';

void main() {
  group('PASETO v4 Tests', () {
    /// Загружаем тестовые векторы из JSON-файла
    final vectors = PasetoTestVectors.fromJsonFile('test/vectors/v4.json');

    group('v4.local (Encryption/Decryption)', () {
      /// Основные тесты шифрования/дешифрования, проверяющие поддержку спецификации
      test('Шифрование и дешифрование с валидным ключом', () async {
        // Arrange
        final secretKey =
            SecretKeyData(Uint8List.fromList(List.filled(32, 42)));
        final content = 'Тестовое сообщение';
        final package = Package(
          content: utf8.encode(content),
          footer: utf8.encode('{"kid":"test-key"}'),
        );

        // Act
        final encrypted = await LocalV4.encrypt(
          package,
          secretKey: secretKey,
        );

        final token = Token(
          header: LocalV4.header,
          payload: encrypted,
          footer: package.footer,
        );

        final decrypted = await token.decryptLocalMessage(
          secretKey: secretKey,
        );

        // Assert
        expect(utf8.decode(decrypted.package.content), content);
        expect(utf8.decode(decrypted.package.footer!), '{"kid":"test-key"}');
      });

      test('Дешифрование с неверным ключом выбрасывает исключение', () async {
        // Arrange
        final secretKey1 =
            SecretKeyData(Uint8List.fromList(List.filled(32, 42)));
        final secretKey2 =
            SecretKeyData(Uint8List.fromList(List.filled(32, 24)));
        final content = 'Тестовое сообщение';
        final package = Package(
          content: utf8.encode(content),
        );

        // Act
        final encrypted = await LocalV4.encrypt(
          package,
          secretKey: secretKey1,
        );

        final token = Token(
          header: LocalV4.header,
          payload: encrypted,
          footer: null,
        );

        // Assert
        expect(
          () => token.decryptLocalMessage(secretKey: secretKey2),
          throwsA(isA<SecretBoxAuthenticationError>()),
        );
      });

      test('Implicit Assertions работают корректно', () async {
        // Arrange
        final secretKey =
            SecretKeyData(Uint8List.fromList(List.filled(32, 42)));
        final content = 'Тестовое сообщение';
        final implicit = utf8.encode('{"context":"test-context"}');
        final package = Package(
          content: utf8.encode(content),
        );

        // Act
        final encrypted = await LocalV4.encrypt(
          package,
          secretKey: secretKey,
          implicit: implicit,
        );

        final token = Token(
          header: LocalV4.header,
          payload: encrypted,
          footer: null,
        );

        // Дешифрование с правильными implicit assertions
        final decrypted = await token.decryptLocalMessage(
          secretKey: secretKey,
          implicit: implicit,
        );

        // Assert
        expect(utf8.decode(decrypted.package.content), content);

        // Дешифрование с неправильными implicit assertions должно выбрасывать исключение
        expect(
          () => token.decryptLocalMessage(
            secretKey: secretKey,
            implicit: utf8.encode('{"context":"wrong-context"}'),
          ),
          throwsA(isA<SecretBoxAuthenticationError>()),
        );
      });

      /// Тесты из тестовых векторов стандарта (совместимость)
      group('Стандартные векторы v4.local (успешные)', () {
        for (final testCase
            in vectors.localVectors.where((v) => !v.expectFail)) {
          test(testCase.name, () async {
            // Arrange
            final secretKey = testCase.secretKey;
            final tokenObj = await Token.fromString(testCase.token);

            // Act & Assert - при использовании правильного ключа не должно быть исключений
            await expectLater(
              tokenObj.decryptLocalMessage(
                secretKey: secretKey,
                implicit: testCase.implicitBytes,
              ),
              completes,
            );
          });
        }
      });

      // Тестируем случаи ошибок из тестовых векторов
      group('Стандартные векторы v4.local (с ошибками)', () {
        for (final testCase
            in vectors.localVectors.where((v) => v.expectFail)) {
          test(testCase.name, () async {
            // Arrange
            final secretKey = testCase.secretKey;
            final tokenObj = await Token.fromString(testCase.token);

            // Assert - должно быть исключение
            expectLater(
              tokenObj.decryptLocalMessage(
                secretKey: secretKey,
                implicit: testCase.implicitBytes,
              ),
              throwsA(anything),
            );
          });
        }
      });
    });

    group('v4.public (Signing/Verification)', () {
      /// Основные тесты подписи/проверки, проверяющие поддержку спецификации
      test('Подпись и проверка с валидной парой ключей', () async {
        // Arrange
        final keyPair = await PublicV4.generateKeyPair();
        final content = 'Тестовое сообщение';
        final package = Package(
          content: utf8.encode(content),
          footer: utf8.encode('{"kid":"test-key"}'),
        );

        // Act
        final signed = await PublicV4.sign(
          package,
          secretKey: keyPair.privateKey,
        );

        final token = Token(
          header: PublicV4.header,
          payload: signed,
          footer: package.footer,
        );

        final verified = await token.verifyPublicMessage(
          publicKey: keyPair.publicKey,
        );

        // Assert
        expect(utf8.decode(verified.package.content), content);
        expect(utf8.decode(verified.package.footer!), '{"kid":"test-key"}');
      });

      test('Проверка с неверным публичным ключом выбрасывает исключение',
          () async {
        // Arrange
        final keyPair1 = await PublicV4.generateKeyPair();
        final keyPair2 = await PublicV4.generateKeyPair();
        final content = 'Тестовое сообщение';
        final package = Package(
          content: utf8.encode(content),
        );

        // Act
        final signed = await PublicV4.sign(
          package,
          secretKey: keyPair1.privateKey,
        );

        final token = Token(
          header: PublicV4.header,
          payload: signed,
          footer: null,
        );

        // Assert
        expect(
          () => token.verifyPublicMessage(publicKey: keyPair2.publicKey),
          throwsA(isA<SignatureVerificationError>()),
        );
      });

      test('Implicit Assertions работают корректно при подписи', () async {
        // Arrange
        final keyPair = await PublicV4.generateKeyPair();
        final content = 'Тестовое сообщение';
        final implicit = utf8.encode('{"context":"test-context"}');
        final package = Package(
          content: utf8.encode(content),
        );

        // Act
        final signed = await PublicV4.sign(
          package,
          secretKey: keyPair.privateKey,
          implicit: implicit,
        );

        final token = Token(
          header: PublicV4.header,
          payload: signed,
          footer: null,
        );

        // Проверка с правильными implicit assertions
        final verified = await token.verifyPublicMessage(
          publicKey: keyPair.publicKey,
          implicit: implicit,
        );

        // Assert
        expect(utf8.decode(verified.package.content), content);

        // Проверка с неправильными implicit assertions должна выбрасывать исключение
        expect(
          () => token.verifyPublicMessage(
            publicKey: keyPair.publicKey,
            implicit: utf8.encode('{"context":"wrong-context"}'),
          ),
          throwsA(isA<SignatureVerificationError>()),
        );
      });

      /// Тесты из тестовых векторов стандарта (совместимость)
      group('Стандартные векторы v4.public (успешные)', () {
        for (final testCase in vectors.publicVectors
            .where((v) => !v.expectFail && v.hasPublicKey)) {
          test(testCase.name, () async {
            // Arrange
            final publicKey = testCase.publicKeyData!;
            final tokenObj = await Token.fromString(testCase.token);

            // Act & Assert - при использовании правильного ключа не должно быть исключений
            await expectLater(
              tokenObj.verifyPublicMessage(
                publicKey: publicKey,
                implicit: testCase.implicitBytes,
              ),
              completes,
            );
          });
        }
      });

      // Тестируем случаи ошибок из тестовых векторов
      group('Стандартные векторы v4.public (с ошибками)', () {
        for (final testCase
            in vectors.publicVectors.where((v) => v.expectFail)) {
          test(testCase.name, () async {
            // Проверяем только, если есть публичный ключ, иначе пропускаем тест
            if (testCase.hasPublicKey) {
              // Arrange
              final publicKey = testCase.publicKeyData!;
              final tokenObj = await Token.fromString(testCase.token);

              // Assert - должно быть исключение
              expectLater(
                tokenObj.verifyPublicMessage(
                  publicKey: publicKey,
                  implicit: testCase.implicitBytes,
                ),
                throwsA(anything),
              );
            } else {
              // Если нет ключа, просто проверяем, что токен не парсится
              expect(
                () async => await Token.fromString(testCase.token),
                throwsA(anything),
              );
            }
          });
        }
      });
    });

    group('Ключевые особенности PASETO v4', () {
      test('Key Commitment обеспечивается в v4.local', () async {
        // Arrange - создаем два разных ключа
        final key1 = SecretKeyData(Uint8List.fromList(List.filled(32, 1)));
        final key2 = SecretKeyData(Uint8List.fromList(List.filled(32, 2)));
        final content = 'Тестовое сообщение для проверки key commitment';
        final package = Package(
          content: utf8.encode(content),
          footer: utf8.encode('{}'),
        );

        // Act - шифруем сообщение с первым ключом
        final encrypted = await LocalV4.encrypt(
          package,
          secretKey: key1,
        );

        final token = Token(
          header: LocalV4.header,
          payload: encrypted,
          footer: package.footer,
        );

        // Assert - расшифровка с первым ключом должна работать
        final decrypted = await token.decryptLocalMessage(secretKey: key1);
        expect(utf8.decode(decrypted.package.content), content);

        // Проверяем, что расшифровка со вторым ключом должна выбрасывать исключение
        expect(
          () => token.decryptLocalMessage(secretKey: key2),
          throwsA(isA<SecretBoxAuthenticationError>()),
          reason: 'v4.local должен обеспечивать key commitment',
        );
      });

      test('Модификация payload нарушает целостность сообщения', () async {
        // Arrange
        final secretKey =
            SecretKeyData(Uint8List.fromList(List.filled(32, 42)));
        final content = 'Тестовое сообщение';
        final package = Package(
          content: utf8.encode(content),
        );

        // Act - шифруем сообщение
        final encrypted = await LocalV4.encrypt(
          package,
          secretKey: secretKey,
        );

        final token = Token(
          header: LocalV4.header,
          payload: encrypted,
          footer: null,
        );

        // Получаем строковое представление токена
        final tokenString = token.toString();

        // Модифицируем токен, изменив один байт в payload
        final parts = tokenString.split('.');
        final modifiedPayload =
            '${parts[2].substring(0, parts[2].length - 1)}X';
        final modifiedToken = '${parts[0]}.${parts[1]}.$modifiedPayload';

        final modifiedTokenObj = await Token.fromString(modifiedToken);

        // Assert - должно быть исключение при расшифровке модифицированного токена
        expect(
          () => modifiedTokenObj.decryptLocalMessage(secretKey: secretKey),
          throwsA(isA<SecretBoxAuthenticationError>()),
          reason:
              'Модифицированный токен должен выбрасывать исключение при проверке',
        );
      });

      test('Модификация footer нарушает целостность сообщения', () async {
        // Arrange
        final secretKey =
            SecretKeyData(Uint8List.fromList(List.filled(32, 42)));
        final content = 'Тестовое сообщение';
        final package = Package(
          content: utf8.encode(content),
          footer: utf8.encode('{"kid":"test-key"}'),
        );

        // Act - шифруем сообщение
        final encrypted = await LocalV4.encrypt(
          package,
          secretKey: secretKey,
        );

        final token = Token(
          header: LocalV4.header,
          payload: encrypted,
          footer: package.footer,
        );

        // Получаем строковое представление токена
        final tokenString = token.toString();

        // Модифицируем токен, изменив footer
        final parts = tokenString.split('.');
        final modifiedFooter =
            base64Url.encode(utf8.encode('{"kid":"modified"}'));
        final modifiedToken =
            '${parts[0]}.${parts[1]}.${parts[2]}.$modifiedFooter';

        final modifiedTokenObj = await Token.fromString(modifiedToken);

        // Assert - должно быть исключение при расшифровке модифицированного токена
        expect(
          () => modifiedTokenObj.decryptLocalMessage(secretKey: secretKey),
          throwsA(isA<SecretBoxAuthenticationError>()),
          reason: 'Модифицированный footer должен нарушать целостность токена',
        );
      });
    });
  });
}
