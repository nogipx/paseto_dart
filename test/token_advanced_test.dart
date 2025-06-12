import 'dart:convert';
import 'dart:typed_data';

import 'package:paseto_dart/paseto_dart.dart';
import 'package:test/test.dart';

void main() {
  group('Token Advanced Tests', () {
    group('fromString Advanced Tests', () {
      test('Token.fromString обрабатывает валидные токены', () async {
        // Создаем реальный токен для тестирования
        final secretKey = SecretKey([
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
          0x8f,
        ]);

        final message = await Message.encryptString(
          '{"test": "data"}',
          version: Version.v4,
          secretKey: secretKey,
          footer: utf8.encode('footer'),
        );

        final tokenString = message.toToken.toTokenString;

        // Парсим токен обратно
        final parsedToken = await Token.fromString(tokenString);

        expect(parsedToken.header.version, equals(Version.v4));
        expect(parsedToken.header.purpose, equals(Purpose.local));
        expect(parsedToken.footer, equals(utf8.encode('footer')));
      });

      test('Token.fromString с валидными данными', () async {
        // Тест с валидным префиксом версии и достаточными данными
        final header = Header(version: Version.v4, purpose: Purpose.local);
        final payload = PayloadLocal(
          secretBox: null,
          nonce: Mac(Uint8List.fromList(
              List.generate(32, (i) => i))), // 32 байта для nonce
          payloadBytes: Uint8List.fromList(
              List.generate(64, (i) => i)), // Достаточно данных
        );
        final token = Token(header: header, payload: payload, footer: null);

        final tokenString = token.toTokenString;
        final parsedToken = await Token.fromString(tokenString);

        expect(parsedToken.header.version, equals(Version.v4));
        expect(parsedToken.header.purpose, equals(Purpose.local));
      });

      test('Token.fromString error cases', () async {
        // Некорректный префикс версии
        await expectLater(
          () => Token.fromString('x4.local.data'),
          throwsA(isA<FormatException>().having(
            (e) => e.message,
            'message',
            contains('Token version must start with "v"'),
          )),
        );

        // Неподдерживаемая версия
        await expectLater(
          () => Token.fromString('v99.local.data'),
          throwsA(isA<FormatException>().having(
            (e) => e.message,
            'message',
            contains('Unsupported token version'),
          )),
        );

        // Некорректный purpose
        await expectLater(
          () => Token.fromString('v4.invalid.data'),
          throwsA(isA<FormatException>().having(
            (e) => e.message,
            'message',
            contains('Unsupported token purpose'),
          )),
        );
      });
    });

    group('decodePayload Tests', () {
      test('decodePayload для local payload', () {
        final header = Header(version: Version.v4, purpose: Purpose.local);

        // Создаем валидные байты payload
        final nonce = Uint8List.fromList(List.generate(32, (i) => i));
        final ciphertext = Uint8List.fromList(List.generate(64, (i) => i + 32));
        final payloadBytes = Uint8List.fromList(nonce + ciphertext);

        final encodedPayload = SafeBase64.encode(payloadBytes);

        final payload = Token.decodePayload(encodedPayload, header: header);

        expect(payload, isA<PayloadLocal>());
        final localPayload = payload as PayloadLocal;
        expect(localPayload.nonce?.bytes, equals(nonce));
        expect(localPayload.payloadBytes, equals(payloadBytes));
      });

      test('decodePayload для public payload', () {
        final header = Header(version: Version.v4, purpose: Purpose.public);

        // Создаем валидные байты payload (message + signature)
        final message = utf8.encode('{"test": "message"}');
        final signature = Uint8List.fromList(
            List.generate(64, (i) => i)); // Ed25519 = 64 bytes
        final payloadBytes = Uint8List.fromList(message + signature);

        final encodedPayload = SafeBase64.encode(payloadBytes);

        final payload = Token.decodePayload(encodedPayload, header: header);

        expect(payload, isA<PayloadPublic>());
        final publicPayload = payload as PayloadPublic;
        expect(publicPayload.message, equals(message));
        expect(publicPayload.signature, equals(signature));
      });

      test('decodePayload error handling для слишком коротких данных', () {
        final localHeader = Header(version: Version.v4, purpose: Purpose.local);
        final shortPayload =
            SafeBase64.encode([1, 2, 3]); // Меньше 32 байт для nonce

        expect(
          () => Token.decodePayload(shortPayload, header: localHeader),
          throwsA(isA<FormatException>().having(
            (e) => e.message,
            'message',
            contains('Invalid token payload length'),
          )),
        );

        final publicHeader =
            Header(version: Version.v4, purpose: Purpose.public);
        final shortPublicPayload =
            SafeBase64.encode([1, 2, 3]); // Меньше 64 байт для signature

        expect(
          () => Token.decodePayload(shortPublicPayload, header: publicHeader),
          throwsA(isA<FormatException>().having(
            (e) => e.message,
            'message',
            contains('Invalid token payload length'),
          )),
        );
      });
    });

    group('PreAuthentication Encoding Tests', () {
      test('standardPreAuthenticationEncoding', () {
        final header = Header(version: Version.v4, purpose: Purpose.local);
        final payload = PayloadLocal(
          secretBox: null,
          nonce: Mac(Uint8List.fromList(List.generate(32, (i) => i))),
          payloadBytes: [1, 2, 3],
        );
        final token = Token(
          header: header,
          payload: payload,
          footer: utf8.encode('footer'),
        );

        final pae = token.standardPreAuthenticationEncoding;
        expect(pae, isNotEmpty);
        expect(pae, isA<Uint8List>());
      });

      test('localAADPreAuthenticationEncoding', () {
        final header = Header(version: Version.v4, purpose: Purpose.local);
        final payload = PayloadLocal(
          secretBox: null,
          nonce: Mac(Uint8List.fromList(List.generate(32, (i) => i))),
          payloadBytes: [1, 2, 3],
        );
        final token = Token(
          header: header,
          payload: payload,
          footer: utf8.encode('footer'),
        );

        final pae = token.localAADPreAuthenticationEncoding;
        expect(pae, isNotEmpty);
        expect(pae, isA<Uint8List>());
      });

      test('localAADPreAuthenticationEncoding error handling', () {
        // Тест с non-local payload
        final publicPayload = PayloadPublic(message: utf8.encode('test'));
        final publicToken = Token(
          header: Header(version: Version.v4, purpose: Purpose.public),
          payload: publicPayload,
          footer: null,
        );

        expect(
          () => publicToken.localAADPreAuthenticationEncoding,
          throwsA(isA<TypeError>()),
        );

        // Тест с payload без nonce
        final localPayloadWithoutNonce = PayloadLocal(
          secretBox: null,
          nonce: null,
          payloadBytes: [1, 2, 3],
        );
        final localTokenWithoutNonce = Token(
          header: Header(version: Version.v4, purpose: Purpose.local),
          payload: localPayloadWithoutNonce,
          footer: null,
        );

        expect(
          () => localTokenWithoutNonce.localAADPreAuthenticationEncoding,
          throwsA(isA<UnsupportedError>()),
        );
      });

      test('preAuthenticationEncoding static method', () {
        final header = Header(version: Version.v4, purpose: Purpose.local);
        final payload = PayloadLocal(
          secretBox: null,
          nonce: Mac(Uint8List.fromList(List.generate(32, (i) => i))),
        );

        final pae1 = Token.preAuthenticationEncoding(
          header: header,
          payload: payload,
          footer: utf8.encode('footer'),
          implicit: [],
        );
        expect(pae1, isNotEmpty);

        final pae2 = Token.preAuthenticationEncoding(
          header: header,
          payload: payload,
          footer: null,
          implicit: utf8.encode('implicit'),
        );
        expect(pae2, isNotEmpty);
        expect(
            pae2,
            isNot(equals(
                pae1))); // Разные параметры должны давать разные результаты
      });

      test('preAuthenticationEncoding с PayloadPublic', () {
        final header = Header(version: Version.v4, purpose: Purpose.public);
        final payload = PayloadPublic(
          message: utf8.encode('{"test": "message"}'),
          signature: Uint8List.fromList(List.generate(64, (i) => i)),
        );

        final pae = Token.preAuthenticationEncoding(
          header: header,
          payload: payload,
          footer: utf8.encode('footer'),
          implicit: [],
        );
        expect(pae, isNotEmpty);
      });
    });

    group('Integration Tests with Real Tokens', () {
      test('Полный цикл с local tokens', () async {
        final secretKey = SecretKey([
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
          0x8f,
        ]);

        // Создаем токен
        final message = await Message.encryptString(
          '{"data": "test"}',
          version: Version.v4,
          secretKey: secretKey,
        );

        final token = message.toToken;
        final tokenString = token.toTokenString;

        // Парсим обратно
        final parsedToken = await Token.fromString(tokenString);

        // Проверяем PAE
        final originalPae = token.standardPreAuthenticationEncoding;
        final parsedPae = parsedToken.standardPreAuthenticationEncoding;
        expect(parsedPae, equals(originalPae));

        // Дешифруем
        final decryptedMessage = await parsedToken.decryptLocalMessage(
          secretKey: secretKey,
        );
        expect(decryptedMessage.stringContent, equals('{"data": "test"}'));
      });

      test('Полный цикл с public tokens', () async {
        final algorithm = Ed25519();
        final keyPair = await algorithm.newKeyPair();
        final publicKey = await keyPair.extractPublicKey();

        // Создаем токен
        final message = await Message.signString(
          '{"announcement": "test"}',
          version: Version.v4,
          keyPair: keyPair,
        );

        final token = message.toToken;
        final tokenString = token.toTokenString;

        // Парсим обратно
        final parsedToken = await Token.fromString(tokenString);

        // Проверяем PAE
        final originalPae = token.standardPreAuthenticationEncoding;
        final parsedPae = parsedToken.standardPreAuthenticationEncoding;
        expect(parsedPae, equals(originalPae));

        // Верифицируем
        final verifiedMessage = await parsedToken.verifyPublicMessage(
          publicKey: publicKey,
        );
        expect(
            verifiedMessage.stringContent, equals('{"announcement": "test"}'));
      });
    });
  });
}
