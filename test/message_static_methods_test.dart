import 'dart:convert';

import 'package:paseto_dart/paseto_dart.dart';
import 'package:test/test.dart';

void main() {
  group('Message Static Methods Tests', () {
    group('encryptString Tests', () {
      test('Message.encryptString создает зашифрованное сообщение', () async {
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

        const content = '{"user": "alice", "role": "admin"}';

        final message = await Message.encryptString(
          content,
          version: Version.v4,
          secretKey: secretKey,
        );

        expect(message.header.version, equals(Version.v4));
        expect(message.header.purpose, equals(Purpose.local));
        expect(message.stringContent, equals(content));
        expect(message.jsonContent, equals({"user": "alice", "role": "admin"}));
        expect(message.payload, isA<PayloadLocal>());
      });

      test('Message.encryptString с footer', () async {
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

        const content = 'Secret message';
        final footer = utf8.encode('{"kid": "test-key"}');

        final message = await Message.encryptString(
          content,
          version: Version.v4,
          secretKey: secretKey,
          footer: footer,
        );

        expect(message.header.version, equals(Version.v4));
        expect(message.header.purpose, equals(Purpose.local));
        expect(message.stringContent, equals(content));
        expect(message.package.footer, equals(footer));
        expect(message.package.stringFooter, equals('{"kid": "test-key"}'));
        expect(message.package.jsonFooter, equals({"kid": "test-key"}));
      });

      test('Message.encryptString с разными типами контента', () async {
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

        // Простой текст
        final textMessage = await Message.encryptString(
          'Hello, World!',
          version: Version.v4,
          secretKey: secretKey,
        );
        expect(textMessage.stringContent, equals('Hello, World!'));
        expect(textMessage.jsonContent, isNull);

        // JSON
        final jsonMessage = await Message.encryptString(
          '{"test": true}',
          version: Version.v4,
          secretKey: secretKey,
        );
        expect(jsonMessage.stringContent, equals('{"test": true}'));
        expect(jsonMessage.jsonContent, equals({"test": true}));

        // Пустая строка
        final emptyMessage = await Message.encryptString(
          '',
          version: Version.v4,
          secretKey: secretKey,
        );
        expect(emptyMessage.stringContent, equals(''));
        expect(emptyMessage.jsonContent, isNull);
      });
    });

    group('signString Tests', () {
      test('Message.signString создает подписанное сообщение', () async {
        final algorithm = Ed25519();
        final keyPair = await algorithm.newKeyPair();

        const content = '{"user": "bob", "action": "login"}';

        final message = await Message.signString(
          content,
          version: Version.v4,
          keyPair: keyPair,
        );

        expect(message.header.version, equals(Version.v4));
        expect(message.header.purpose, equals(Purpose.public));
        expect(message.stringContent, equals(content));
        expect(message.jsonContent, equals({"user": "bob", "action": "login"}));
        expect(message.payload, isA<PayloadPublic>());
      });

      test('Message.signString с footer', () async {
        final algorithm = Ed25519();
        final keyPair = await algorithm.newKeyPair();

        const content = 'Public announcement';
        final footer = utf8.encode('{"issuer": "test-org"}');

        final message = await Message.signString(
          content,
          version: Version.v4,
          keyPair: keyPair,
          footer: footer,
        );

        expect(message.header.version, equals(Version.v4));
        expect(message.header.purpose, equals(Purpose.public));
        expect(message.stringContent, equals(content));
        expect(message.package.footer, equals(footer));
        expect(message.package.stringFooter, equals('{"issuer": "test-org"}'));
        expect(message.package.jsonFooter, equals({"issuer": "test-org"}));
      });

      test('Message.signString с разными типами контента', () async {
        final algorithm = Ed25519();
        final keyPair = await algorithm.newKeyPair();

        // Простой текст
        final textMessage = await Message.signString(
          'Public message',
          version: Version.v4,
          keyPair: keyPair,
        );
        expect(textMessage.stringContent, equals('Public message'));
        expect(textMessage.jsonContent, isNull);

        // JSON
        final jsonMessage = await Message.signString(
          '{"announcement": "New release"}',
          version: Version.v4,
          keyPair: keyPair,
        );
        expect(jsonMessage.stringContent,
            equals('{"announcement": "New release"}'));
        expect(
            jsonMessage.jsonContent, equals({"announcement": "New release"}));

        // Пустая строка
        final emptyMessage = await Message.signString(
          '',
          version: Version.v4,
          keyPair: keyPair,
        );
        expect(emptyMessage.stringContent, equals(''));
        expect(emptyMessage.jsonContent, isNull);
      });
    });

    group('Integration Tests', () {
      test('Полный цикл: encrypt -> token -> decrypt', () async {
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

        const originalContent = '{"secret": "data", "timestamp": 12345}';
        final footer = utf8.encode('{"kid": "key-123"}');

        // Шифруем
        final encryptedMessage = await Message.encryptString(
          originalContent,
          version: Version.v4,
          secretKey: secretKey,
          footer: footer,
        );

        // Получаем токен
        final token = encryptedMessage.toToken;
        final tokenString = token.toTokenString;
        expect(tokenString, startsWith('v4.local.'));

        // Парсим токен обратно
        final parsedToken = await Token.fromString(tokenString);
        expect(parsedToken.header.version, equals(Version.v4));
        expect(parsedToken.header.purpose, equals(Purpose.local));

        // Дешифруем
        final decryptedMessage = await parsedToken.decryptLocalMessage(
          secretKey: secretKey,
        );

        expect(decryptedMessage.stringContent, equals(originalContent));
        expect(decryptedMessage.jsonContent,
            equals({"secret": "data", "timestamp": 12345}));
        expect(decryptedMessage.package.footer, equals(footer));
      });

      test('Полный цикл: sign -> token -> verify', () async {
        final algorithm = Ed25519();
        final keyPair = await algorithm.newKeyPair();
        final publicKey = await keyPair.extractPublicKey();

        const originalContent = '{"public": "announcement", "version": 1}';
        final footer = utf8.encode('{"issuer": "authority"}');

        // Подписываем
        final signedMessage = await Message.signString(
          originalContent,
          version: Version.v4,
          keyPair: keyPair,
          footer: footer,
        );

        // Получаем токен
        final token = signedMessage.toToken;
        final tokenString = token.toTokenString;
        expect(tokenString, startsWith('v4.public.'));

        // Парсим токен обратно
        final parsedToken = await Token.fromString(tokenString);
        expect(parsedToken.header.version, equals(Version.v4));
        expect(parsedToken.header.purpose, equals(Purpose.public));

        // Верифицируем
        final verifiedMessage = await parsedToken.verifyPublicMessage(
          publicKey: publicKey,
        );

        expect(verifiedMessage.stringContent, equals(originalContent));
        expect(verifiedMessage.jsonContent,
            equals({"public": "announcement", "version": 1}));
        expect(verifiedMessage.package.footer, equals(footer));
      });
    });
  });
}
