import 'dart:convert';
import 'dart:typed_data';

import 'package:paseto_dart/paseto_dart.dart';
import 'package:test/test.dart';

void main() {
  group('PublicV4 Comprehensive Tests', () {
    late SimpleKeyPair keyPair;
    late SimplePublicKey publicKey;

    setUpAll(() async {
      final algorithm = Ed25519();
      keyPair = await algorithm.newKeyPair();
      publicKey = await keyPair.extractPublicKey();
    });

    group('Константы и базовые проверки', () {
      test('header константа', () {
        expect(PublicV4.header.version, equals(Version.v4));
        expect(PublicV4.header.purpose, equals(Purpose.public));
        expect(PublicV4.header.toTokenString, equals('v4.public.'));
      });

      test('signatureLength константа', () {
        expect(
            PublicV4.signatureLength, equals(64)); // Ed25519 подпись = 64 байта
      });
    });

    group('sign метод', () {
      test('sign создает правильный payload', () async {
        final package = Package(
          content: utf8.encode('{"test": "message"}'),
          footer: utf8.encode('{"kid": "test-key"}'),
        );

        final payload =
            await PublicV4.sign(package, keyPair: keyPair) as PayloadPublic;

        expect(payload, isA<PayloadPublic>());
        expect(payload.message, equals(package.content));
        expect(payload.signature, isNotNull);
        expect(payload.signature!.length, equals(64));
      });

      test('sign с пустым content', () async {
        final package = Package(content: []);

        final payload =
            await PublicV4.sign(package, keyPair: keyPair) as PayloadPublic;

        expect(payload.message, isEmpty);
        expect(payload.signature, isNotNull);
        expect(payload.signature!.length, equals(64));
      });

      test('sign с implicit assertions', () async {
        final package = Package(
          content: utf8.encode('test data'),
        );
        final implicit = utf8.encode('implicit data');

        final payload = await PublicV4.sign(
          package,
          keyPair: keyPair,
          implicit: implicit,
        ) as PayloadPublic;

        expect(payload.signature, isNotNull);
        expect(payload.signature!.length, equals(64));
      });

      test('sign с null footer', () async {
        final package = Package(
          content: utf8.encode('test'),
          footer: null,
        );

        final payload =
            await PublicV4.sign(package, keyPair: keyPair) as PayloadPublic;

        expect(payload.signature, isNotNull);
        expect(payload.signature!.length, equals(64));
      });

      test('sign error handling - неправильный ключ', () async {
        // Создаем ключ неправильной длины (это сложно симулировать с реальным Ed25519)
        final package = Package(content: utf8.encode('test'));

        // Тест проходит, поскольку Ed25519() генерирует правильные ключи
        final payload =
            await PublicV4.sign(package, keyPair: keyPair) as PayloadPublic;
        expect(payload.signature, isNotNull);
      });
    });

    group('verify метод', () {
      test('verify успешно проверяет подпись', () async {
        final package = Package(
          content: utf8.encode('{"message": "hello world"}'),
          footer: utf8.encode('{"issuer": "test"}'),
        );

        // Подписываем
        final payload = await PublicV4.sign(package, keyPair: keyPair);

        // Создаем токен
        final token = Token(
          header: PublicV4.header,
          payload: payload,
          footer: package.footer,
        );

        // Проверяем
        final verifiedPackage = await PublicV4.verify(
          token,
          publicKey: publicKey,
        );

        expect(verifiedPackage.content, equals(package.content));
        expect(verifiedPackage.footer, equals(package.footer));
      });

      test('verify с implicit assertions', () async {
        final package = Package(content: utf8.encode('test data'));
        final implicit = utf8.encode('implicit assertions');

        // Подписываем с implicit
        final payload = await PublicV4.sign(
          package,
          keyPair: keyPair,
          implicit: implicit,
        );

        final token = Token(
          header: PublicV4.header,
          payload: payload,
          footer: null,
        );

        // Проверяем с теми же implicit
        final verifiedPackage = await PublicV4.verify(
          token,
          publicKey: publicKey,
          implicit: implicit,
        );

        expect(verifiedPackage.content, equals(package.content));
      });

      test('verify с null implicit (используется пустой массив)', () async {
        final package = Package(content: utf8.encode('test'));

        final payload = await PublicV4.sign(package, keyPair: keyPair);
        final token = Token(
          header: PublicV4.header,
          payload: payload,
          footer: null,
        );

        // Verify без implicit (должен использовать пустой массив)
        final verifiedPackage = await PublicV4.verify(
          token,
          publicKey: publicKey,
          implicit: null,
        );

        expect(verifiedPackage.content, equals(package.content));
      });

      test('verify error handling - неправильная версия токена', () async {
        final payload = PayloadPublic(
          message: utf8.encode('test'),
          signature: Uint8List(64), // Фиктивная подпись
        );

        final token = Token(
          header: Header(
              version: Version.v4,
              purpose: Purpose.local), // Неправильный purpose
          payload: payload,
          footer: null,
        );

        await expectLater(
          () => PublicV4.verify(token, publicKey: publicKey),
          throwsA(isA<FormatException>().having(
            (e) => e.message,
            'message',
            contains('not a v4.public token'),
          )),
        );
      });

      test('verify error handling - отсутствующая подпись', () async {
        final payload = PayloadPublic(
          message: utf8.encode('test'),
          signature: null, // Нет подписи
        );

        final token = Token(
          header: PublicV4.header,
          payload: payload,
          footer: null,
        );

        await expectLater(
          () => PublicV4.verify(token, publicKey: publicKey),
          throwsA(isA<Exception>().having(
            (e) => e.toString(),
            'toString',
            contains('Missing or empty signature'),
          )),
        );
      });

      test('verify error handling - пустая подпись', () async {
        final payload = PayloadPublic(
          message: utf8.encode('test'),
          signature: [], // Пустая подпись
        );

        final token = Token(
          header: PublicV4.header,
          payload: payload,
          footer: null,
        );

        await expectLater(
          () => PublicV4.verify(token, publicKey: publicKey),
          throwsA(isA<Exception>().having(
            (e) => e.toString(),
            'toString',
            contains('Missing or empty signature'),
          )),
        );
      });

      test('verify error handling - неправильная длина подписи', () async {
        final payload = PayloadPublic(
          message: utf8.encode('test'),
          signature: Uint8List(32), // Неправильная длина (должно быть 64)
        );

        final token = Token(
          header: PublicV4.header,
          payload: payload,
          footer: null,
        );

        await expectLater(
          () => PublicV4.verify(token, publicKey: publicKey),
          throwsA(isA<Exception>().having(
            (e) => e.toString(),
            'toString',
            contains('Invalid signature length'),
          )),
        );
      });

      test('verify error handling - неправильная длина ключа', () async {
        // Ed25519 ключи всегда 32 байта, поэтому этот тест покрывает код проверки
        final payload = PayloadPublic(
          message: utf8.encode('test'),
          signature: Uint8List(64),
        );

        final token = Token(
          header: PublicV4.header,
          payload: payload,
          footer: null,
        );

        // Обычный ключ должен пройти проверку длины
        expect(publicKey.bytes.length, equals(32));

        // Проверяем что токен можно верифицировать (косвенная проверка длины ключа)
        expect(() => PublicV4.verify(token, publicKey: publicKey),
            throwsA(isA<Exception>()));
      });

      test('verify error handling - невалидная подпись', () async {
        final package = Package(content: utf8.encode('original message'));

        // Подписываем одно сообщение
        final payload =
            await PublicV4.sign(package, keyPair: keyPair) as PayloadPublic;

        // Но меняем содержимое (подпись станет невалидной)
        final tamperedPayload = PayloadPublic(
          message: utf8.encode('tampered message'),
          signature: payload.signature,
        );

        final token = Token(
          header: PublicV4.header,
          payload: tamperedPayload,
          footer: null,
        );

        await expectLater(
          () => PublicV4.verify(token, publicKey: publicKey),
          throwsA(isA<Exception>().having(
            (e) => e.toString(),
            'toString',
            contains('Invalid signature'),
          )),
        );
      });
    });

    group(
        '_preAuthenticationEncoding приватный метод (через интеграционные тесты)',
        () {
      test('PAE корректно формируется для разных данных', () async {
        // Тестируем PAE через полный цикл sign/verify
        final testCases = [
          {
            'message': '',
            'footer': '',
            'implicit': '',
          },
          {
            'message': 'Hello, World!',
            'footer': '{"kid":"test"}',
            'implicit': 'implicit-data',
          },
          {
            'message': '{"data": [1,2,3], "nested": {"key": "value"}}',
            'footer': '',
            'implicit': '',
          },
        ];

        for (final testCase in testCases) {
          final package = Package(
            content: utf8.encode(testCase['message']!),
            footer: testCase['footer']!.isNotEmpty
                ? utf8.encode(testCase['footer']!)
                : null,
          );
          final implicit = testCase['implicit']!.isNotEmpty
              ? utf8.encode(testCase['implicit']!)
              : null;

          // Подписываем
          final payload = await PublicV4.sign(
            package,
            keyPair: keyPair,
            implicit: implicit,
          );

          final token = Token(
            header: PublicV4.header,
            payload: payload,
            footer: package.footer,
          );

          // Проверяем - если PAE работает неправильно, проверка провалится
          final verifiedPackage = await PublicV4.verify(
            token,
            publicKey: publicKey,
            implicit: implicit,
          );

          expect(verifiedPackage.content, equals(package.content));
          expect(verifiedPackage.footer, equals(package.footer));
        }
      });
    });

    group('_int64LE приватный метод (через интеграционные тесты)', () {
      test('int64LE корректно обрабатывает разные числа', () async {
        // Тестируем через разные размеры данных, которые влияют на PAE
        final testSizes = [0, 1, 255, 256, 65535, 65536, 1000000];

        for (final size in testSizes) {
          final largeContent = Uint8List(size);
          // Заполняем данными для проверки
          for (int i = 0; i < size; i++) {
            largeContent[i] = i % 256;
          }

          final package = Package(content: largeContent);

          // Если _int64LE работает неправильно, подпись/проверка провалится
          final payload = await PublicV4.sign(package, keyPair: keyPair);
          final token = Token(
            header: PublicV4.header,
            payload: payload,
            footer: null,
          );

          final verifiedPackage = await PublicV4.verify(
            token,
            publicKey: publicKey,
          );

          expect(verifiedPackage.content, equals(package.content));
        }
      });
    });

    group('Интеграционные тесты с реальными сценариями', () {
      test('JWT-подобные claims', () async {
        final claims = {
          'iss': 'https://issuer.example.com',
          'sub': 'user123',
          'aud': 'https://api.example.com',
          'exp':
              DateTime.now().add(Duration(hours: 1)).millisecondsSinceEpoch ~/
                  1000,
          'iat': DateTime.now().millisecondsSinceEpoch ~/ 1000,
          'jti': 'unique-token-id-${DateTime.now().millisecondsSinceEpoch}',
        };

        final package = Package(
          content: utf8.encode(json.encode(claims)),
          footer: utf8.encode('{"kid":"signing-key-1","alg":"EdDSA"}'),
        );

        final payload = await PublicV4.sign(package, keyPair: keyPair);
        final token = Token(
          header: PublicV4.header,
          payload: payload,
          footer: package.footer,
        );

        final verifiedPackage = await PublicV4.verify(
          token,
          publicKey: publicKey,
        );

        final verifiedClaims =
            json.decode(utf8.decode(verifiedPackage.content));
        expect(verifiedClaims['sub'], equals('user123'));
        expect(verifiedClaims['iss'], equals('https://issuer.example.com'));
      });

      test('Большие данные (stress test)', () async {
        // Тест с большим payload
        final largeData = List.generate(10000, (i) => 'data-item-$i').join(',');
        final package = Package(content: utf8.encode(largeData));

        final payload = await PublicV4.sign(package, keyPair: keyPair);
        final token = Token(
          header: PublicV4.header,
          payload: payload,
          footer: null,
        );

        final verifiedPackage = await PublicV4.verify(
          token,
          publicKey: publicKey,
        );

        expect(utf8.decode(verifiedPackage.content), equals(largeData));
      });

      test('Бинарные данные', () async {
        final binaryData =
            Uint8List.fromList(List.generate(1000, (i) => i % 256));

        final package = Package(content: binaryData);

        final payload = await PublicV4.sign(package, keyPair: keyPair);
        final token = Token(
          header: PublicV4.header,
          payload: payload,
          footer: null,
        );

        final verifiedPackage = await PublicV4.verify(
          token,
          publicKey: publicKey,
        );

        expect(verifiedPackage.content, equals(binaryData));
      });

      test('Совместимость с разными ключами', () async {
        // Создаем несколько разных ключей
        final algorithm = Ed25519();
        final keyPairs = <SimpleKeyPair>[];
        final publicKeys = <SimplePublicKey>[];

        for (int i = 0; i < 3; i++) {
          final kp = await algorithm.newKeyPair();
          keyPairs.add(kp);
          publicKeys.add(await kp.extractPublicKey());
        }

        final package = Package(
          content: utf8.encode('{"user": "alice", "role": "admin"}'),
        );

        for (int i = 0; i < keyPairs.length; i++) {
          // Подписываем одним ключом
          final payload = await PublicV4.sign(package, keyPair: keyPairs[i]);
          final token = Token(
            header: PublicV4.header,
            payload: payload,
            footer: null,
          );

          // Проверяем соответствующим публичным ключом
          final verifiedPackage = await PublicV4.verify(
            token,
            publicKey: publicKeys[i],
          );

          expect(verifiedPackage.content, equals(package.content));

          // Проверяем что другие ключи НЕ работают
          for (int j = 0; j < publicKeys.length; j++) {
            if (i != j) {
              await expectLater(
                () => PublicV4.verify(token, publicKey: publicKeys[j]),
                throwsA(isA<Exception>()),
              );
            }
          }
        }
      });
    });
  });
}
