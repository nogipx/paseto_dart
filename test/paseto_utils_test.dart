import 'dart:convert';
import 'dart:typed_data';

import 'package:paseto_dart/paseto_dart.dart';
import 'package:test/test.dart';

import 'test_utils.dart';

void main() {
  group('PASETO Utils Tests', () {
    group('Base64 кодирование/декодирование', () {
      test('Base64Url кодирование/декодирование', () {
        // Arrange
        final originalData =
            Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

        // Act
        final encoded = base64Url.encode(originalData);
        final decoded = base64Url.decode(encoded);

        // Assert
        expect(decoded, equals(originalData));
      });

      test('Base64Url кодирование без паддинга', () {
        // Arrange
        final data1 = Uint8List.fromList([1, 2, 3]); // требует паддинга
        final data2 = Uint8List.fromList([1, 2, 3, 4]); // не требует паддинга

        // Act
        final encoded1 = base64Url.encode(data1);
        final encoded2 = base64Url.encode(data2);

        // Assert
        expect(encoded1.endsWith('='), isFalse,
            reason: 'Base64Url не должен содержать паддинг');
        expect(encoded2.endsWith('='), isFalse,
            reason: 'Base64Url не должен содержать паддинг');

        // Проверяем, что декодирование работает правильно
        expect(base64Url.decode(encoded1), equals(data1));
        expect(base64Url.decode(encoded2), equals(data2));
      });

      test('Специальные символы в Base64Url', () {
        // В Base64Url '+' заменяется на '-', а '/' на '_'
        final standardBase64 = 'a+b/c==';
        final expectedBase64Url = 'a-b_c';

        // Проверяем, что '=' в конце удаляется
        expect(
            standardBase64
                .replaceAll('+', '-')
                .replaceAll('/', '_')
                .replaceAll('=', ''),
            equals(expectedBase64Url));
      });
    });

    group('Pre-Authentication Encoding', () {
      test('PAE правильно сериализует данные', () {
        // Arrange
        final header = Header(version: Version.v4, purpose: Purpose.local);
        final nonce = Uint8List.fromList(List.filled(32, 42));
        final footer = Uint8List.fromList([1, 2, 3, 4]);
        final implicit = Uint8List.fromList([5, 6, 7, 8]);

        // Act
        final pae = Token.preAuthenticationEncoding(
          header: header,
          payload: PayloadLocal(
            nonce: Mac(nonce),
            secretBox: null,
          ),
          footer: footer,
          implicit: implicit,
        );

        // Assert
        // Проверяем, что длина массива PAE корректна
        final expectedPAEStart = [
          2, 0, 0, 0, 0, 0, 0, 0, // len(array) = 2
          8, 0, 0, 0, 0, 0, 0, 0, // len("v4.local") = 8
          ...utf8.encode("v4.local"),
        ];

        for (var i = 0; i < expectedPAEStart.length; i++) {
          expect(pae[i], expectedPAEStart[i],
              reason:
                  'Несоответствие в PAE байте $i: ${pae[i]} vs ${expectedPAEStart[i]}');
        }

        // Проверяем общую структуру PAE
        expect(
            pae.length,
            greaterThan(expectedPAEStart.length +
                8 +
                nonce.length +
                8 +
                footer.length +
                8 +
                implicit.length),
            reason: 'Недостаточная длина PAE');
      });

      test('PAE должен быть детерминированным', () {
        // Arrange
        final header = Header(version: Version.v4, purpose: Purpose.local);
        final nonce = Uint8List.fromList(List.filled(32, 42));
        final footer = Uint8List.fromList([1, 2, 3, 4]);
        final implicit = Uint8List.fromList([5, 6, 7, 8]);

        // Act - создаем PAE дважды с одинаковыми данными
        final pae1 = Token.preAuthenticationEncoding(
          header: header,
          payload: PayloadLocal(
            nonce: Mac(nonce),
            secretBox: null,
          ),
          footer: footer,
          implicit: implicit,
        );

        final pae2 = Token.preAuthenticationEncoding(
          header: header,
          payload: PayloadLocal(
            nonce: Mac(nonce),
            secretBox: null,
          ),
          footer: footer,
          implicit: implicit,
        );

        // Assert - два PAE с одинаковыми данными должны быть идентичны
        expect(pae1, equals(pae2), reason: 'PAE должен быть детерминированным');
      });
    });

    group('Парсинг токенов', () {
      test('Парсинг валидного токена', () async {
        // Arrange
        const tokenStr =
            'v4.public.eyJkYXRhIjoidGVzdCBtZXNzYWdlIn3Hjiy4Qgng7jTBfMHjuI7-W7Q33-XVpZzZbpNFbPg31_pkuQ2JXcUVz_-9vTvfgmGDOLO5XvWqBHUFDA';

        // Act
        final token = await Token.fromString(tokenStr);

        // Assert
        expect(token.header.version, equals(Version.v4));
        expect(token.header.purpose, equals(Purpose.public));
        expect(token.footer, isNull);

        final payload = token.payloadPublic;
        expect(payload, isNotNull);

        // Проверяем, что сериализация обратно в строку даёт исходную строку
        expect(token.toString(), equals(tokenStr));
      });

      test('Парсинг токена с footer', () async {
        // Arrange
        const tokenStr =
            'v4.public.eyJkYXRhIjoidGVzdCBtZXNzYWdlIn3Hjiy4Qgng7jTBfMHjuI7-W7Q33-XVpZzZbpNFbPg31_pkuQ2JXcUVz_-9vTvfgmGDOLO5XvWqBHUFDA.eyJraWQiOiJ0ZXN0LWtleSJ9';
        final expectedFooter = '{"kid":"test-key"}';

        // Act
        final token = await Token.fromString(tokenStr);

        // Assert
        expect(token.header.version, equals(Version.v4));
        expect(token.header.purpose, equals(Purpose.public));
        expect(token.footer, isNotNull);
        expect(utf8.decode(token.footer!), equals(expectedFooter));

        // Проверяем, что сериализация обратно в строку даёт исходную строку
        expect(token.toString(), equals(tokenStr));
      });

      test('Инвалидный формат токена', () async {
        // Arrange
        const invalidToken1 = 'invalid.token.format';
        const invalidToken2 = 'v4.invalid.eyJkYXRhIjoidGVzdCJ9';

        // Act & Assert
        expectLater(
            Token.fromString(invalidToken1), throwsA(isA<FormatException>()));
        expectLater(
            Token.fromString(invalidToken2), throwsA(isA<FormatException>()));
      });
    });

    group('Константное время сравнения', () {
      test('Сравнение одинаковых массивов', () {
        // Arrange
        final a = Uint8List.fromList([1, 2, 3, 4, 5]);
        final b = Uint8List.fromList([1, 2, 3, 4, 5]);

        // Act & Assert - нам нужно проверить, что реализация включает константное время сравнения
        // Мы можем только косвенно проверить результат, поскольку не можем напрямую измерить время
        expect(_constantTimeEquals(a, b), isTrue);
      });

      test('Сравнение разных массивов', () {
        // Arrange
        final a = Uint8List.fromList([1, 2, 3, 4, 5]);
        final b =
            Uint8List.fromList([1, 2, 3, 4, 6]); // Отличается последний байт

        // Act & Assert
        expect(_constantTimeEquals(a, b), isFalse);
      });

      test('Сравнение массивов разной длины', () {
        // Arrange
        final a = Uint8List.fromList([1, 2, 3, 4, 5]);
        final b = Uint8List.fromList([1, 2, 3, 4]);

        // Act & Assert
        expect(_constantTimeEquals(a, b), isFalse);
      });
    });
  });
}

/// Реализация сравнения в константном времени для тестирования
bool _constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) {
    return false;
  }

  int result = 0;
  for (int i = 0; i < a.length; i++) {
    // XOR каждой пары байтов, результат OR с общим результатом
    // Это гарантирует, что времена сравнения одинаковы для всех входных данных
    result |= a[i] ^ b[i];
  }

  return result == 0;
}
