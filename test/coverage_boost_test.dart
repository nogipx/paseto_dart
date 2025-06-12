import 'dart:convert';
import 'dart:typed_data';

import 'package:paseto_dart/paseto_dart.dart';
import 'package:test/test.dart';

void main() {
  group('Coverage Boost Tests', () {
    group('Package Tests', () {
      test('Package stringContent и jsonContent', () {
        // Тест с валидным JSON
        final jsonPackage = Package(
          content: utf8.encode('{"test": "value", "number": 42}'),
        );

        expect(jsonPackage.stringContent,
            equals('{"test": "value", "number": 42}'));
        expect(
            jsonPackage.jsonContent, equals({"test": "value", "number": 42}));

        // Тест с невалидным JSON
        final textPackage = Package(
          content: utf8.encode('plain text'),
        );

        expect(textPackage.stringContent, equals('plain text'));
        expect(textPackage.jsonContent, isNull);

        // Тест с бинарными данными
        final binaryPackage = Package(
          content: [0, 255, 128, 64],
        );

        expect(binaryPackage.stringContent, isNotNull);
        expect(binaryPackage.jsonContent, isNull);
      });

      test('Package stringFooter и jsonFooter', () {
        // Тест с JSON footer
        final packageWithJsonFooter = Package(
          content: utf8.encode('content'),
          footer: utf8.encode('{"kid": "test-key"}'),
        );

        expect(
            packageWithJsonFooter.stringFooter, equals('{"kid": "test-key"}'));
        expect(packageWithJsonFooter.jsonFooter, equals({"kid": "test-key"}));

        // Тест без footer
        final packageWithoutFooter = Package(
          content: utf8.encode('content'),
        );

        expect(packageWithoutFooter.stringFooter, isNull);
        expect(packageWithoutFooter.jsonFooter, isNull);

        // Тест с невалидным JSON в footer
        final packageWithTextFooter = Package(
          content: utf8.encode('content'),
          footer: utf8.encode('plain footer'),
        );

        expect(packageWithTextFooter.stringFooter, equals('plain footer'));
        expect(packageWithTextFooter.jsonFooter, isNull);
      });

      test('Package calculateNonce', () async {
        final package = Package(
          content: utf8.encode('test content'),
          footer: utf8.encode('footer'),
        );

        final secretKey = SecretKey([1, 2, 3, 4, 5, 6, 7, 8]);
        final nonce = await package.calculateNonce(preNonce: secretKey);

        expect(nonce.bytes.length, greaterThan(0));
      });
    });

    group('Header Tests', () {
      test('Header toTokenString', () {
        final header = Header(version: Version.v4, purpose: Purpose.local);
        expect(header.toTokenString, equals('v4.local.'));

        final publicHeader =
            Header(version: Version.v4, purpose: Purpose.public);
        expect(publicHeader.toTokenString, equals('v4.public.'));
      });

      test('Header toString', () {
        final header = Header(version: Version.v4, purpose: Purpose.local);
        expect(header.toString(), contains('v4'));
        expect(header.toString(), contains('local'));
      });
    });

    group('PayloadPublic Tests', () {
      test('PayloadPublic stringMessage и jsonContent', () {
        // С валидным JSON
        final jsonPayload = PayloadPublic(
          message: utf8.encode('{"user": "alice", "role": "admin"}'),
        );

        expect(jsonPayload.stringMessage,
            equals('{"user": "alice", "role": "admin"}'));
        expect(jsonPayload.jsonContent,
            equals({"user": "alice", "role": "admin"}));

        // С невалидным JSON
        final textPayload = PayloadPublic(
          message: utf8.encode('plain message'),
        );

        expect(textPayload.stringMessage, equals('plain message'));
        expect(textPayload.jsonContent, isNull);
      });

      test('PayloadPublic toTokenString', () {
        final message = utf8.encode('test message');

        // Без подписи
        final payloadWithoutSig = PayloadPublic(message: message);
        final tokenStr1 = payloadWithoutSig.toTokenString;
        expect(tokenStr1, isNotEmpty);

        // С подписью
        final signature = Uint8List.fromList(List.generate(64, (i) => i));
        final payloadWithSig = PayloadPublic(
          message: message,
          signature: signature,
        );
        final tokenStr2 = payloadWithSig.toTokenString;
        expect(tokenStr2, isNotEmpty);
        expect(tokenStr2.length, greaterThan(tokenStr1.length));
      });
    });

    group('PayloadLocal Tests', () {
      test('PayloadLocal toTokenString с payloadBytes', () {
        final payloadBytes = Uint8List.fromList([1, 2, 3, 4, 5]);
        final payload = PayloadLocal(
          secretBox: null,
          nonce: null,
          payloadBytes: payloadBytes,
        );

        final tokenStr = payload.toTokenString;
        expect(tokenStr, isNotEmpty);

        // Проверяем что можем декодировать обратно
        final decoded = SafeBase64.decode(tokenStr);
        expect(decoded, equals(payloadBytes));
      });

      test('PayloadLocal toTokenString с компонентами', () {
        final nonce = Mac(Uint8List.fromList(List.generate(32, (i) => i)));
        final ciphertext =
            Uint8List.fromList(List.generate(100, (i) => i + 50));
        final secretBox = SecretBox(
          ciphertext,
          nonce: Uint8List.fromList(List.generate(12, (i) => i)),
          mac: Mac(Uint8List.fromList(List.generate(16, (i) => i))),
        );

        final payload = PayloadLocal(
          secretBox: secretBox,
          nonce: nonce,
        );

        final tokenStr = payload.toTokenString;
        expect(tokenStr, isNotEmpty);
      });
    });

    group('Token Tests', () {
      test('Token payloadLocal и payloadPublic геттеры', () {
        final localPayload = PayloadLocal(
          secretBox: null,
          nonce: null,
          payloadBytes: [1, 2, 3],
        );

        final localToken = Token(
          header: Header(version: Version.v4, purpose: Purpose.local),
          payload: localPayload,
          footer: null,
        );

        expect(localToken.payloadLocal, equals(localPayload));
        expect(() => localToken.payloadPublic, throwsA(isA<TypeError>()));

        final publicPayload = PayloadPublic(message: utf8.encode('test'));
        final publicToken = Token(
          header: Header(version: Version.v4, purpose: Purpose.public),
          payload: publicPayload,
          footer: null,
        );

        expect(publicToken.payloadPublic, equals(publicPayload));
        expect(() => publicToken.payloadLocal, throwsA(isA<TypeError>()));
      });

      test('Token toTokenString', () {
        final payload = PayloadLocal(
          secretBox: null,
          nonce: null,
          payloadBytes: [1, 2, 3],
        );

        // Без footer
        final tokenWithoutFooter = Token(
          header: Header(version: Version.v4, purpose: Purpose.local),
          payload: payload,
          footer: null,
        );

        final tokenStr1 = tokenWithoutFooter.toTokenString;
        expect(tokenStr1, startsWith('v4.local.'));
        expect(tokenStr1.split('.').length, equals(3));

        // С footer
        final tokenWithFooter = Token(
          header: Header(version: Version.v4, purpose: Purpose.local),
          payload: payload,
          footer: utf8.encode('footer'),
        );

        final tokenStr2 = tokenWithFooter.toTokenString;
        expect(tokenStr2, startsWith('v4.local.'));
        expect(tokenStr2.split('.').length, equals(4));

        // С пустым footer
        final tokenWithEmptyFooter = Token(
          header: Header(version: Version.v4, purpose: Purpose.local),
          payload: payload,
          footer: [],
        );

        final tokenStr3 = tokenWithEmptyFooter.toTokenString;
        expect(tokenStr3, startsWith('v4.local.'));
        expect(tokenStr3.split('.').length,
            equals(3)); // пустой footer не добавляется
      });
    });

    group('Message Tests', () {
      test('Message геттеры stringContent и jsonContent', () {
        final package = Package(
          content: utf8.encode('{"message": "hello"}'),
        );

        final payload = PayloadLocal(
          secretBox: null,
          nonce: null,
          payloadBytes: [1, 2, 3],
        );

        final message = Message(
          header: Header(version: Version.v4, purpose: Purpose.local),
          package: package,
          payload: payload,
        );

        expect(message.stringContent, equals('{"message": "hello"}'));
        expect(message.jsonContent, equals({"message": "hello"}));
      });

      test('Message toToken', () {
        final package = Package(
          content: utf8.encode('content'),
          footer: utf8.encode('footer'),
        );

        final payload = PayloadLocal(
          secretBox: null,
          nonce: null,
          payloadBytes: [1, 2, 3],
        );

        final message = Message(
          header: Header(version: Version.v4, purpose: Purpose.local),
          package: package,
          payload: payload,
        );

        final token = message.toToken;
        expect(token.header, equals(message.header));
        expect(token.payload, equals(message.payload));
        expect(token.footer, equals(package.footer));
      });
    });

    group('Error Handling Tests', () {
      test('Token fromString с некорректными данными', () async {
        await expectLater(
          () => Token.fromString(''),
          throwsA(isA<ArgumentError>()),
        );

        await expectLater(
          () => Token.fromString('invalid'),
          throwsA(isA<ArgumentError>()),
        );

        await expectLater(
          () => Token.fromString('a.b'),
          throwsA(isA<ArgumentError>()),
        );

        await expectLater(
          () => Token.fromString('invalid.local.data'),
          throwsA(isA<FormatException>()),
        );

        await expectLater(
          () => Token.fromString('v4.invalid.data'),
          throwsA(isA<FormatException>()),
        );
      });

      test('Token decryptLocalMessage error handling', () async {
        final publicPayload = PayloadPublic(message: utf8.encode('test'));
        final publicToken = Token(
          header: Header(version: Version.v4, purpose: Purpose.public),
          payload: publicPayload,
          footer: null,
        );

        final secretKey = SecretKey([1, 2, 3, 4, 5, 6, 7, 8]);

        await expectLater(
          () => publicToken.decryptLocalMessage(secretKey: secretKey),
          throwsA(isA<UnsupportedError>()),
        );
      });

      test('Token verifyPublicMessage error handling', () async {
        final localPayload = PayloadLocal(
          secretBox: null,
          nonce: null,
          payloadBytes: [1, 2, 3],
        );
        final localToken = Token(
          header: Header(version: Version.v4, purpose: Purpose.local),
          payload: localPayload,
          footer: null,
        );

        final algorithm = Ed25519();
        final keyPair = await algorithm.newKeyPair();
        final publicKey = await keyPair.extractPublicKey();

        await expectLater(
          () => localToken.verifyPublicMessage(publicKey: publicKey),
          throwsA(isA<UnsupportedError>()),
        );
      });
    });
  });
}
