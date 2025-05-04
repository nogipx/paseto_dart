import 'dart:convert';
import 'dart:typed_data';

import 'package:paseto_dart/paseto_dart.dart';
import 'package:test/test.dart';

void main() {
  group('PASETO Utils Tests', () {
    group('Base64 кодирование/декодирование', () {
      test('Base64Url кодирование/декодирование', () {
        // Arrange
        final originalData =
            Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

        // Act
        final encoded = SafeBase64.encode(originalData);
        final decoded = SafeBase64.decode(encoded);

        // Assert
        expect(decoded, equals(originalData));
      });

      test('Base64Url кодирование без паддинга', () {
        // Arrange
        final data1 = Uint8List.fromList([1, 2, 3]); // требует паддинга
        final data2 = Uint8List.fromList([1, 2, 3, 4]); // не требует паддинга

        // Act
        final encoded1 = SafeBase64.encode(data1);
        final encoded2 = SafeBase64.encode(data2);

        // Assert
        expect(encoded1.endsWith('='), isFalse,
            reason: 'Base64Url не должен содержать паддинг');
        expect(encoded2.endsWith('='), isFalse,
            reason: 'Base64Url не должен содержать паддинг');

        // Проверяем, что декодирование работает правильно
        expect(SafeBase64.decode(encoded1), equals(data1));
        expect(SafeBase64.decode(encoded2), equals(data2));
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
          4, 0, 0, 0, 0, 0, 0, 0, // len(array) = 4
          8, 0, 0, 0, 0, 0, 0, 0, // len("v4.local") = 8
          ...utf8.encode("v4.local"),
        ];

        for (var i = 0; i < expectedPAEStart.length; i++) {
          expect(
            pae[i],
            expectedPAEStart[i],
            reason: 'Несоответствие в PAE байте $i:'
                ' ${pae[i]} vs ${expectedPAEStart[i]}',
          );
        }

        // Проверяем общую структуру PAE
        final expectedPAELength = expectedPAEStart.length +
            8 +
            nonce.length +
            8 +
            footer.length +
            8 +
            implicit.length;
        expect(
          pae.length,
          greaterThanOrEqualTo(expectedPAELength),
          reason: 'Недостаточная длина PAE',
        );
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
        expect(token.toTokenString, equals(tokenStr));
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
        expect(token.toTokenString, equals(tokenStr));
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
  });
}
