import 'dart:convert';
import 'package:paseto_dart/paseto_dart.dart';
import 'package:test/test.dart';
import 'vectors.dart';

void publicTest(Vectors vectors) {
  final versionName = vectors.version.name;
  if (vectors.public.isEmpty) {
    fail('No public vectors for $versionName');
  }
  final success = vectors.public.where((v) => !v.expectFail && v.hasPublicKey);
  final failed = vectors.public.where((v) => v.expectFail && v.hasPublicKey);

  group('Test $versionName.public Vectors', () {
    for (final vector in success) {
      test('Vector ${vector.name}', () async {
        // Arrange
        final publicKey = vector.publicKeyData!;
        final token = await Token.fromString(vector.token);
        final implicitBytes = vector.implicitAssertionBytes;

        // Act
        final verified = await token.verifyPublicMessage(
          publicKey: publicKey,
          implicit: implicitBytes,
        );

        // Assert
        if (vector.payload != null) {
          expect(utf8.decode(verified.package.content), vector.payload);
        }

        // Проверяем совпадение footer
        if (vector.footer.isNotEmpty) {
          expect(utf8.decode(verified.package.footer!), vector.footer);
        }
      });
    }

    for (final vector in failed) {
      test('Vector ${vector.name}', () async {
        // Arrange
        final publicKey = vector.publicKeyData!;

        // Act & Assert - ожидаем ошибку
        expectLater(
          Token.fromString(vector.token)
              .then((token) => token.verifyPublicMessage(
                    publicKey: publicKey,
                    implicit: vector.implicitAssertionBytes,
                  )),
          throwsA(anything), // Ожидаем любую ошибку
        );
      });
    }
  });
}

void localTest(Vectors vectors) {
  final versionName = vectors.version.name;
  if (vectors.local.isEmpty) {
    fail('No local vectors for $versionName');
  }
  final success = vectors.local.where((v) => !v.expectFail);
  final failed = vectors.local.where((v) => v.expectFail);

  group('Test $versionName.local Vectors', () {
    for (final vector in success) {
      test('Vector ${vector.name}', () async {
        // Arrange
        final secretKey = vector.secretKey;
        final token = await Token.fromString(vector.token);
        final implicitBytes = vector.implicitAssertionBytes;

        // Act
        final decrypted = await token.decryptLocalMessage(
          secretKey: secretKey,
          implicit: implicitBytes,
        );

        // Assert
        if (vector.payload != null) {
          expect(utf8.decode(decrypted.package.content), vector.payload);
        }

        // Проверяем совпадение footer
        if (vector.footer.isNotEmpty) {
          expect(utf8.decode(decrypted.package.footer!), vector.footer);
        }
      });
    }

    for (final vector in failed) {
      test('Vector ${vector.name}', () async {
        // Arrange
        final secretKey = vector.secretKey;

        // Act & Assert - ожидаем ошибку
        expectLater(
          Token.fromString(vector.token)
              .then((token) => token.decryptLocalMessage(
                    secretKey: secretKey,
                    implicit: vector.implicitAssertionBytes,
                  )),
          throwsA(anything), // Ожидаем любую ошибку
        );
      });
    }
  });
}
