import 'dart:typed_data';

import 'package:paseto_dart/paseto_dart.dart';
import 'package:test/test.dart';

import 'test_vectors.dart';

Uint8List hexToBytes(String hex) {
  var result = Uint8List((hex.length) ~/ 2);
  for (var i = 0; i < hex.length; i += 2) {
    result[i ~/ 2] = int.parse(hex.substring(i, i + 2), radix: 16);
  }
  return result;
}

void main() {
  group('PASERK v4 Test Vectors', () {
    test('k4.local encoding/decoding', () {
      final vector = k4TestVectors['k4.local']!;
      final keyBytes = hexToBytes(vector['key']!);

      // Проверяем длину symmetric key
      expect(keyBytes.length, equals(32),
          reason: 'k4.local symmetric key must be 32 bytes');

      final key = K4LocalKey(keyBytes);
      expect(key.toString(), equals(vector['paserk']));

      final decoded = K4LocalKey.fromString(vector['paserk']!);
      expect(decoded.rawBytes, equals(keyBytes));
    });

    test('k4.secret encoding/decoding', () {
      final vector = k4TestVectors['k4.secret']!;
      final keyBytes = hexToBytes(vector['secret']!);

      // Проверяем длину Ed25519 secret key
      expect(keyBytes.length, equals(64),
          reason: 'Ed25519 secret key must be 64 bytes (seed + public key)');

      // Проверяем формат Ed25519 secret key
      final seed = keyBytes.sublist(0, 32);
      final pubkey = keyBytes.sublist(32);
      expect(pubkey.length, equals(32),
          reason: 'Last 32 bytes must be Ed25519 public key');

      final key = K4SecretKey(keyBytes);
      expect(key.toString(), equals(vector['paserk']));

      final decoded = K4SecretKey.fromString(vector['paserk']!);
      expect(decoded.rawBytes, equals(keyBytes));
    });

    test('k4.public encoding/decoding', () {
      final vector = k4TestVectors['k4.public']!;
      final keyBytes = hexToBytes(vector['public']!);
      final key = K4PublicKey(keyBytes);
      expect(key.toString(), equals(vector['paserk']));

      // Проверяем что публичный ключ Ed25519 имеет правильную длину
      expect(key.rawBytes.length, equals(32),
          reason: 'Ed25519 public key should be 32 bytes');

      final decoded = K4PublicKey.fromString(vector['paserk']!);
      expect(decoded.rawBytes, equals(keyBytes));
    });

    test('k4.local-wrap wrapping/unwrapping', () async {
      final vector = k4TestVectors['k4.local-wrap']!;
      final keyBytes = hexToBytes(vector['unwrapped']!);
      final password = vector['password']!;

      // Проверяем длину unwrapped key
      expect(keyBytes.length, equals(32),
          reason: 'k4.local-wrap unwrapped key must be 32 bytes');

      final originalKey = K4LocalKey(keyBytes);

      // Проверяем конкретный тестовый вектор
      final wrappedFromVector =
          await K4LocalWrap.unwrap(vector['paserk']!, password);
      expect(wrappedFromVector.rawBytes, equals(originalKey.rawBytes));

      // Проверяем длину unwrapped key после unwrap
      expect(wrappedFromVector.rawBytes.length, equals(32),
          reason: 'k4.local-wrap unwrapped key must be 32 bytes after unwrap');

      // Проверяем round-trip wrapping/unwrapping
      final wrapped = await K4LocalWrap.wrap(originalKey, password);
      // Проверяем что использует стандартный протокол 'pie'
      expect(wrapped.toString(), contains('k4.local-wrap.pie.'),
          reason: 'Should use standard pie wrapping protocol');

      final unwrapped = await K4LocalWrap.unwrap(wrapped.toString(), password);
      expect(unwrapped.rawBytes, equals(originalKey.rawBytes));

      // Проверяем длину unwrapped key после round-trip
      expect(unwrapped.rawBytes.length, equals(32),
          reason:
              'k4.local-wrap unwrapped key must be 32 bytes after round-trip');

      // Проверяем неверный пароль
      expect(
        () => K4LocalWrap.unwrap(wrapped.toString(), 'wrong-password'),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('k4.secret-wrap wrapping/unwrapping', () async {
      final vector = k4TestVectors['k4.secret-wrap']!;
      final keyBytes = hexToBytes(vector['unwrapped']!);
      final password = vector['password']!;

      // Проверяем длину unwrapped key
      expect(keyBytes.length, equals(64),
          reason: 'k4.secret-wrap unwrapped key must be 64 bytes');

      final originalKey = K4SecretKey(keyBytes);

      // Проверяем конкретный тестовый вектор
      final wrappedFromVector =
          await K4SecretWrap.unwrap(vector['paserk']!, password);
      expect(wrappedFromVector.rawBytes, equals(originalKey.rawBytes));

      // Проверяем длину unwrapped key после unwrap
      expect(wrappedFromVector.rawBytes.length, equals(64),
          reason: 'k4.secret-wrap unwrapped key must be 64 bytes after unwrap');

      // Проверяем round-trip wrapping/unwrapping
      final wrapped = await K4SecretWrap.wrap(originalKey, password);
      // Проверяем что использует стандартный протокол 'pie'
      expect(wrapped.toString(), contains('k4.secret-wrap.pie.'),
          reason: 'Should use standard pie wrapping protocol');

      final unwrapped = await K4SecretWrap.unwrap(wrapped.toString(), password);
      expect(unwrapped.rawBytes, equals(originalKey.rawBytes));

      // Проверяем длину unwrapped key после round-trip
      expect(unwrapped.rawBytes.length, equals(64),
          reason:
              'k4.secret-wrap unwrapped key must be 64 bytes after round-trip');

      // Проверяем неверный пароль
      expect(
        () => K4SecretWrap.unwrap(wrapped.toString(), 'wrong-password'),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('k4.lid generation and comparison', () {
      final vector = k4TestVectors['k4.lid']!;
      final key = K4LocalKey.fromString(vector['key']!);

      final lid = K4Lid.fromKey(key);
      expect(lid.toString(), equals(vector['paserk']));

      final lid2 = K4Lid.fromString(vector['paserk']!);
      expect(lid, equals(lid2));
    });

    test('k4.pid generation and comparison', () {
      final vector = k4TestVectors['k4.pid']!;
      final key = K4PublicKey.fromString(vector['key']!);

      final pid = K4Pid.fromKey(key);
      expect(pid.toString(), equals(vector['paserk']));

      final pid2 = K4Pid.fromString(vector['paserk']!);
      expect(pid, equals(pid2));
    });

    test('k4.sid generation and comparison', () {
      final vector = k4TestVectors['k4.sid']!;
      final key = K4SecretKey.fromString(vector['key']!);

      final sid = K4Sid.fromKey(key);
      expect(sid.toString(), equals(vector['paserk']));

      final sid2 = K4Sid.fromString(vector['paserk']!);
      expect(sid, equals(sid2));
    });

    test('Cross-verification between public and secret keys', () async {
      final secretVector = k4TestVectors['k4.secret']!;
      final publicVector = k4TestVectors['k4.public']!;

      final secretKey = K4SecretKey.fromString(secretVector['paserk']!);
      // Проверяем длину секретного ключа Ed25519 (64 байта = seed + pubkey)
      expect(secretKey.rawBytes.length, equals(64),
          reason: 'Ed25519 secret key must be 64 bytes');

      final derivedPublicKey = await K4PublicKey.fromSecretKey(secretKey);
      // ��роверяем длину публичного ключа Ed25519 (32 байта)
      expect(derivedPublicKey.rawBytes.length, equals(32),
          reason: 'Ed25519 public key must be 32 bytes');

      expect(derivedPublicKey.toString(), equals(publicVector['paserk']));
    });

    test('Invalid key lengths', () {
      expect(
        () => K4LocalKey(Uint8List(31)), // Должно быть 32 байта
        throwsArgumentError,
      );

      expect(
        () => K4SecretKey(Uint8List(63)), // Должно быть 64 байта
        throwsArgumentError,
      );

      expect(
        () => K4PublicKey(Uint8List(31)), // Должно быть 32 байта
        throwsArgumentError,
      );
    });
  });
}
