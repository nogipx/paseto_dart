import 'dart:convert';
import 'dart:typed_data';
import 'package:hex/hex.dart';
import 'package:paseto_dart/paseto_dart.dart';
import 'package:test/test.dart';

void main() {
  group('Node.js-Dart Interoperability Tests', () {
    test('Decrypt Node.js-generated v4.local token in Dart', () async {
      // Тот же ключ что используем в Node.js
      final keyHex =
          "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
      final key = Uint8List.fromList(HEX.decode(keyHex));

      print('Testing Node.js->Dart interoperability');
      print('Key: $keyHex');

      // Здесь токен, сгенерированный Node.js программой
      String nodeToken =
          "v4.local.fR-knUAFi8a-XkEd3LC5OgstDqGpm5PraAM7tQtrFdGQKxZJDTRq1SuUfNZUiwEBTpUYCyzHcr6cqhCsffkJyuuC0jexLJx2W1frsdT79y0-fRmZ9siPGEjky1HSKdbaGpHQqmPBPc2loXxt6H6ygI6mT8gynCxpwARNbpaU5HSjuMOg9n-GtxoELQ5dAXv0p1CBzGJigo5W6euxiOrI2xolJ4Wpdj9MOzwib8Rh2X0pbAoNlRigJDWP7nGMV4L7HhuDqfBXOQNwqOKxuzhllNj_3Cof_kEmbY6iQFqGjTYUK7cldK1FNfGe5Yg";

      if (nodeToken == "PLACEHOLDER_FOR_PYTHON_TOKEN") {
        print(
            '⚠️  Нужно заменить PLACEHOLDER_FOR_PYTHON_TOKEN на реальный токен из Python');
        print(
            'Запустите Python программу и скопируйте сгенерированный токен сюда');

        // Создадим тестовый токен нашей реализацией для проверки
        print('\n=== Создаем тестовый токен нашей реализацией ===');

        final claims = {
          'sub': 'test-user',
          'iss': 'dart-generator',
          'aud': 'java-parser',
          'message': 'Hello from Dart!',
          'number': 42
        };

        // Создаем объект SecretKey из ключа
        final secretKey = SecretKey(key);

        // Создаем пакет с данными
        final package = Package(
          content: utf8.encode(json.encode(claims)),
        );

        // Шифруем пакет с помощью LocalV4
        final encryptedPayload = await LocalV4.encrypt(
          package,
          secretKey: secretKey,
        );

        // Создаем токен из зашифрованного payload
        final dartToken = Token(
          header: LocalV4.header,
          payload: encryptedPayload,
          footer: null,
        );

        print('Dart Token: ${dartToken.toTokenString}');

        // Проверяем что можем расшифровать свой же токен
        final decrypted = await LocalV4.decrypt(
          dartToken,
          secretKey: secretKey,
        );
        final decodedContent = utf8.decode(decrypted.content);
        final decodedClaims = json.decode(decodedContent);
        print('Decrypted claims: $decodedClaims');

        expect(decodedClaims['sub'], 'test-user');
        expect(decodedClaims['message'], 'Hello from Dart!');
        expect(decodedClaims['number'], 42);

        print('✅ Dart self-encryption test passed');
        return;
      }

      print('Node.js Token: $nodeToken');

      try {
        // Пытаемся расшифровать токен сгенерированный в Python
        // Сначала парсим токен
        final token = await Token.fromString(nodeToken);
        final secretKey = SecretKey(key);
        final decrypted = await LocalV4.decrypt(token, secretKey: secretKey);

        print('\n=== Successfully decrypted Node.js token in Dart! ===');
        final decodedContent = utf8.decode(decrypted.content);
        final decodedClaims = json.decode(decodedContent);
        print('Claims: ${json.encode(decodedClaims)}');

        // Проверяем ожидаемые поля
        expect(decodedClaims['sub'], 'test-user');
        expect(decodedClaims['iss'], 'node-generator');
        expect(decodedClaims['aud'], 'dart-parser');
        expect(decodedClaims['message'], 'Hello from Node.js!');
        expect(decodedClaims['number'], 42);

        print('✅ Node.js->Dart interoperability test PASSED!');
      } catch (e) {
        print('❌ Failed to decrypt Node.js token: $e');
        fail('Could not decrypt Node.js-generated token: $e');
      }
    });

    test('Generate Dart token for Node.js to decrypt', () async {
      // Создаем токен в Dart который потом можно расшифровать в Node.js
      final keyHex =
          "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
      final key = Uint8List.fromList(HEX.decode(keyHex));

      final claims = {
        'sub': 'dart-user',
        'iss': 'dart-generator',
        'aud': 'node-parser',
        'message': 'Hello from Dart to Node.js!',
        'number': 123,
        'iat': DateTime.now().toUtc().toIso8601String(),
        'exp': DateTime.now().add(Duration(hours: 1)).toUtc().toIso8601String(),
      };

      // Создаем объект SecretKey из ключа
      final secretKey = SecretKey(key);

      // Создаем пакет с данными
      final package = Package(
        content: utf8.encode(json.encode(claims)),
      );

      // Шифруем пакет с помощью LocalV4
      final encryptedPayload = await LocalV4.encrypt(
        package,
        secretKey: secretKey,
      );

      // Создаем токен из зашифрованного payload
      final dartToken = Token(
        header: LocalV4.header,
        payload: encryptedPayload,
        footer: null,
      );

      print('\n=== Token generated in Dart for Node.js ===');
      print('Key: $keyHex');
      print('Token: ${dartToken.toTokenString}');
      print('Claims: ${json.encode(claims)}');

      // Проверяем что мы сами можем его расшифровать
      final verified = await LocalV4.decrypt(dartToken, secretKey: secretKey);
      final verifiedContent = utf8.decode(verified.content);
      final verifiedClaims = json.decode(verifiedContent);
      expect(verifiedClaims['sub'], 'dart-user');
      expect(verifiedClaims['message'], 'Hello from Dart to Node.js!');

      print('✅ Dart token generated and verified');
      print('📋 Copy this token to test in Node.js application');
    });

    test('Test with multiple formats and edge cases', () async {
      final keyHex =
          "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
      final key = Uint8List.fromList(HEX.decode(keyHex));

      // Тестируем разные типы данных
      final testCases = [
        {
          'name': 'Simple string',
          'claims': {'message': 'Simple test'},
        },
        {
          'name': 'Numbers and booleans',
          'claims': {
            'integer': 42,
            'double': 3.14159,
            'boolean': true,
            'null_value': null,
          },
        },
        {
          'name': 'Arrays and objects',
          'claims': {
            'array': [1, 2, 3, 'four'],
            'object': {'nested': 'value', 'count': 5},
          },
        },
        {
          'name': 'Standard claims',
          'claims': {
            'iss': 'test-issuer',
            'sub': 'test-subject',
            'aud': 'test-audience',
            'exp': DateTime.now()
                .add(Duration(hours: 1))
                .toUtc()
                .toIso8601String(),
            'nbf': DateTime.now().toUtc().toIso8601String(),
            'iat': DateTime.now().toUtc().toIso8601String(),
            'jti': 'test-token-id',
          },
        },
      ];

      for (final testCase in testCases) {
        print('\n--- Testing: ${testCase['name']} ---');

        final claims = testCase['claims'] as Map<String, dynamic>;
        final secretKey = SecretKey(key);
        final package = Package(content: utf8.encode(json.encode(claims)));
        final encryptedPayload =
            await LocalV4.encrypt(package, secretKey: secretKey);
        final token = Token(
            header: LocalV4.header, payload: encryptedPayload, footer: null);
        final decrypted = await LocalV4.decrypt(token, secretKey: secretKey);

        print('Token: ${token.toTokenString.substring(0, 50)}...');
        print('Original: ${json.encode(claims)}');

        final decodedContent = utf8.decode(decrypted.content);
        final decodedClaims = json.decode(decodedContent);
        print('Decrypted: ${json.encode(decodedClaims)}');

        // Проверяем что все поля совпадают
        for (final entry in claims.entries) {
          expect(decodedClaims[entry.key], entry.value,
              reason: 'Field ${entry.key} mismatch in ${testCase['name']}');
        }

        print('✅ ${testCase['name']} test passed');
      }
    });
  });
}
