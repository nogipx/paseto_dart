import 'dart:convert';

import 'package:paseto_dart/paseto_dart.dart';
import 'package:test/test.dart';

import '../../vectors.dart';

void main() {
  final vectors = Vectors.loadV4();

  group('PASETO v4 official vectors', () {
    group('local', () {
      test('has success cases', () {
        expect(vectors.localSuccess, isNotEmpty);
      });

      for (final vector in vectors.localSuccess) {
        test('decrypts ${vector.name}', () async {
          final token = await Token.fromString(vector.token);
          final message = await token.decryptLocalMessage(
            secretKey: vector.secretKey,
            implicit: vector.implicitAssertionBytes,
          );

          if (vector.payloadBytes != null) {
            expect(
                utf8.decode(message.package.content), equals(vector.payload));
          }

          final expectedFooter = vector.footerBytes;
          if (expectedFooter == null) {
            expect(message.package.footer, isNull);
          } else {
            expect(message.package.footer, equals(expectedFooter));
          }
        });
      }

      for (final vector in vectors.localFailures) {
        test('fails ${vector.name}', () async {
          await expectLater(
            () async {
              final token = await Token.fromString(vector.token);
              return token.decryptLocalMessage(
                secretKey: vector.secretKey,
                implicit: vector.implicitAssertionBytes,
              );
            }(),
            throwsA(anything),
          );
        });
      }
    });

    group('public', () {
      test('has success cases', () {
        expect(vectors.publicSuccess, isNotEmpty);
      });

      for (final vector in vectors.publicSuccess) {
        test('verifies ${vector.name}', () async {
          final token = await Token.fromString(vector.token);
          final message = await token.verifyPublicMessage(
            publicKey: vector.publicKeyData!,
            implicit: vector.implicitAssertionBytes,
          );

          if (vector.payloadBytes != null) {
            expect(
                utf8.decode(message.package.content), equals(vector.payload));
          }

          final expectedFooter = vector.footerBytes;
          if (expectedFooter == null) {
            expect(message.package.footer, isNull);
          } else {
            expect(message.package.footer, equals(expectedFooter));
          }
        });
      }

      for (final vector in vectors.publicFailures) {
        test('fails ${vector.name}', () async {
          final token = await Token.fromString(vector.token);

          Future<Message> attempt() async {
            if (vector.publicKeyData != null) {
              return token.verifyPublicMessage(
                publicKey: vector.publicKeyData!,
                implicit: vector.implicitAssertionBytes,
              );
            }

            if (vector.secretKeyData != null) {
              return token.decryptLocalMessage(
                secretKey: vector.secretKeyData!,
                implicit: vector.implicitAssertionBytes,
              );
            }

            throw StateError('No key material for ${vector.name}');
          }

          await expectLater(attempt(), throwsA(anything));
        });
      }
    });
  });
}
