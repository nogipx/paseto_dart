import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:paseto_dart/paseto_dart.dart';
import 'package:test/test.dart';

import 'test_utils.dart';

void main() {
  group('PASETO v2 Compatibility Tests', () {
    final testVectors = jsonDecode(
      File('test/vectors/v2.json').readAsStringSync(),
    ) as Map<String, dynamic>;

    final testCases =
        (testVectors['tests'] as List<dynamic>).cast<Map<String, dynamic>>();

    for (final testCase in testCases) {
      final testName = testCase['name'] as String;
      final expectFail = testCase['expect-fail'] as bool;
      final token = testCase['token'] as String;
      final payload = testCase['payload'] as String?;
      final footer = testCase['footer'] as String;
      final implicitAssertion = testCase['implicit-assertion'] as String;

      test('Test Vector: $testName', () async {
        // Определяем тип токена по префиксу
        final isLocal = token.startsWith('v2.local.');
        final isPublic = token.startsWith('v2.public.');

        if (isLocal) {
          await _testLocalToken(
            testCase: testCase,
            expectFail: expectFail,
            token: token,
            expectedPayload: payload,
            footer: footer,
            implicitAssertion: implicitAssertion,
          );
        } else if (isPublic) {
          await _testPublicToken(
            testCase: testCase,
            expectFail: expectFail,
            token: token,
            expectedPayload: payload,
            footer: footer,
            implicitAssertion: implicitAssertion,
          );
        } else {
          fail('Неизвестный тип токена: $token');
        }
      });
    }
  });
}

Future<void> _testLocalToken({
  required Map<String, dynamic> testCase,
  required bool expectFail,
  required String token,
  required String? expectedPayload,
  required String footer,
  required String implicitAssertion,
}) async {
  final testName = testCase['name'] as String;
  final keyHex = testCase['key'] as String;
  final keyBytes = hexToUint8List(keyHex);
  final secretKey = SecretKeyData(keyBytes);

  final tokenObj = await Token.fromString(token);

  if (expectFail) {
    expect(
      () => tokenObj.decryptLocalMessage(
        secretKey: secretKey,
        // В v2 нет implicit assertions
      ),
      throwsA(isA<Exception>()),
      reason: 'Должна быть ошибка для тестового вектора $testName',
    );
  } else {
    final decrypted = await tokenObj.decryptLocalMessage(
      secretKey: secretKey,
      // В v2 нет implicit assertions
    );

    expect(utf8.decode(decrypted.package.content), expectedPayload);

    // Тест шифрования (проверяем, что можем зашифровать и потом расшифровать)
    if (expectedPayload != null && testCase.containsKey('nonce')) {
      // Создаем пакет с данными для шифрования
      final package = Package(
        content: utf8.encode(expectedPayload),
        footer: footer.isNotEmpty ? utf8.encode(footer) : null,
      );

      // В тесте мы не можем напрямую управлять рандомным nonce,
      // поэтому проверяем просто шифрование/расшифровку
      final payload = await LocalV2.encrypt(
        package,
        secretKey: secretKey,
      );

      final generatedToken = Token(
        header: LocalV2.header,
        payload: payload,
        footer: package.footer,
      );

      final decryptedAgain = await generatedToken.decryptLocalMessage(
        secretKey: secretKey,
      );

      expect(utf8.decode(decryptedAgain.package.content), expectedPayload);
    }
  }
}

Future<void> _testPublicToken({
  required Map<String, dynamic> testCase,
  required bool expectFail,
  required String token,
  required String? expectedPayload,
  required String footer,
  required String implicitAssertion,
}) async {
  final testName = testCase['name'] as String;
  final publicKeyHex = testCase['public-key'] as String;
  final publicKeyBytes = hexToUint8List(publicKeyHex);
  final publicKey = PublicKeyData(publicKeyBytes);

  final tokenObj = await Token.fromString(token);

  if (expectFail) {
    expect(
      () => tokenObj.verifyPublicMessage(
        publicKey: publicKey,
        // В v2 нет implicit assertions
      ),
      throwsA(isA<Exception>()),
      reason: 'Должна быть ошибка для тестового вектора $testName',
    );
  } else {
    final verified = await tokenObj.verifyPublicMessage(
      publicKey: publicKey,
      // В v2 нет implicit assertions
    );

    expect(utf8.decode(verified.package.content), expectedPayload);

    // Тест подписи (проверяем, что можем подписать и потом проверить)
    if (expectedPayload != null && testCase.containsKey('secret-key')) {
      final secretKeyHex = testCase['secret-key'] as String;
      final secretKeyBytes = hexToUint8List(secretKeyHex);

      // Для v2 нужен KeyPair с приватным и публичным ключом
      final keyPair = KeyPair(
        privateKey: SecretKeyData(secretKeyBytes),
        publicKey: publicKey,
      );

      // Создаем пакет с данными для подписи
      final package = Package(
        content: utf8.encode(expectedPayload),
        footer: footer.isNotEmpty ? utf8.encode(footer) : null,
      );

      final payload = await PublicV2.sign(
        package,
        keyPair: keyPair,
      );

      final generatedToken = Token(
        header: PublicV2.header,
        payload: payload,
        footer: package.footer,
      );

      final verifiedAgain = await generatedToken.verifyPublicMessage(
        publicKey: publicKey,
      );

      expect(utf8.decode(verifiedAgain.package.content), expectedPayload);
    }
  }
}
