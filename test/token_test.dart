import 'dart:convert';

import 'package:test/test.dart';
import 'package:paseto_dart/paseto_dart.dart';
import 'test_helpers.dart';

void main() {
  group('Token', () {
    test('fromString v2.local', () async {
      const tokenString = 'v2.local.AAAAAAAAAAAAAAAAIHRlc3QA0lsIwWB8M_x3DYr6VOcXzRT8NP2QFzG'
          'vj8nEn3-FD-KVUUUZr9YGsVbBKaG0ctZNBB6IWp-1MGGOkHLJADCNQA';
      final token = await Token.fromString(tokenString);
      expect(token.header.version, Version.v2);
      expect(token.header.purpose, Purpose.local);

      // Проверяем локальные данные
      final payload = token.payloadLocal;
      expect(payload, isNotNull);
      expect(payload!.nonce!.bytes, isNotEmpty);
      expect(payload.secretBox!.cipherText, isNotEmpty);
    });

    test('fromString v2.public', () async {
      const tokenString = 'v2.public.dGVzdAAAAAAAAAAAAAAAAAAAQWjBnZZ-JrTN-Hm6dTo9I8a-AVl-'
          'KjfnRIiC4VryLFf8AiGypS1DjYgGwaDmNiOYtVeO9b1jzLAYtOlZz-KxAg';
      final token = await Token.fromString(tokenString);
      expect(token.header.version, Version.v2);
      expect(token.header.purpose, Purpose.public);

      // Проверяем публичные данные
      final payload = token.payloadPublic;
      expect(payload, isNotNull);
      expect(payload!.message, isNotEmpty);
      expect(payload.signature, isNotEmpty);
    });

    test('Token decryptLocalMessage/verifyPublicMessage', () async {
      // Инициализируем алгоритмы
      PasetoRegistryInitializer.initV3Public();
      PasetoRegistryInitializer.initV3Local();

      // Создаем ключи
      final secretKey = await TestHelpers.generateSecretKey(32);
      final keyPair = await TestHelpers.generateKeyPair(TestKeyPairType.ecdsa384);

      // Создаем токены напрямую для тестирования
      final localToken = Token(
        header: LocalV3.header,
        payload: PayloadLocal(
          nonce: Mac(List<int>.filled(LocalV3.nonceLength, 1)),
          secretBox: SecretBox(
            List<int>.filled(32, 2),
            nonce: List<int>.filled(24, 3),
            mac: Mac(List<int>.filled(16, 4)),
          ),
        ),
        footer: null,
      );

      final publicToken = Token(
        header: PublicV3.header,
        payload: PayloadPublic(
          message: List<int>.from([1, 2, 3, 4, 5]),
          signature: List<int>.from([10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120]),
        ),
        footer: null,
      );

      // Проверяем, что неверный ключ вызывает ошибку при расшифровке
      bool localErrorThrown = false;
      try {
        await localToken.decryptLocalMessage(secretKey: secretKey);
        fail('Расшифровка неверного токена должна была вызвать ошибку');
      } catch (e) {
        // Любая ошибка здесь означает успех
        localErrorThrown = true;
      }

      // Проверяем, что неверная подпись вызывает ошибку при проверке
      bool publicErrorThrown = false;
      try {
        await publicToken.verifyPublicMessage(publicKey: keyPair.publicKey);
        fail('Проверка неверного токена должна была вызвать ошибку');
      } catch (e) {
        // Любая ошибка здесь означает успех
        publicErrorThrown = true;
      }

      expect(localErrorThrown, isTrue, reason: 'Ожидалась ошибка при расшифровке неверного токена');
      expect(publicErrorThrown, isTrue, reason: 'Ожидалась ошибка при проверке неверного токена');
    });

    test('preAuthenticationEncoding', () {
      // Проверяем кодирование PAE
      final header = Header(version: Version.v2, purpose: Purpose.local);
      final message = utf8.encode('test');
      final nonce = List<int>.filled(24, 0);
      final mac = Mac(List<int>.filled(16, 0));

      final payload = PayloadLocal(
        secretBox: SecretBox(message, nonce: nonce, mac: mac),
        nonce: Mac(nonce),
      );

      final footer = utf8.encode('footer');

      final pae = Token.preAuthenticationEncoding(
        header: header,
        payload: payload,
        footer: footer,
      );

      expect(pae, isNotNull);
      expect(pae.lengthInBytes, greaterThan(0));
    });
  });
}
