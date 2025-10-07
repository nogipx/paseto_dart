import 'dart:typed_data';

import 'package:paseto_dart/paseto_dart.dart';
import 'package:test/test.dart';

import 'test_vectors.dart';

Uint8List hexToBytes(String hex) {
  final result = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < hex.length; i += 2) {
    result[i ~/ 2] = int.parse(hex.substring(i, i + 2), radix: 16);
  }
  return result;
}

String expectString(Map<String, Object> vector, String key) {
  final value = vector[key];
  expect(value, isA<String>(), reason: 'Expected "$key" to be a String');
  return value as String;
}

void main() {
  group('PASERK v4 Test Vectors', () {
    test('k4.local encoding/decoding', () {
      final vector = k4TestVectors['k4.local']!;
      final keyBytes = hexToBytes(expectString(vector, 'key'));

      expect(keyBytes.length, equals(32),
          reason: 'k4.local symmetric key must be 32 bytes');

      final key = K4LocalKey(keyBytes);
      expect(key.toString(), equals(expectString(vector, 'paserk')));

      final decoded = K4LocalKey.fromString(expectString(vector, 'paserk'));
      expect(decoded.rawBytes, equals(keyBytes));
    });

    test('k4.secret encoding/decoding', () {
      final vector = k4TestVectors['k4.secret']!;
      final keyBytes = hexToBytes(expectString(vector, 'secret'));

      expect(keyBytes.length, equals(64),
          reason: 'Ed25519 secret key must be 64 bytes (seed + public key)');

      final seed = keyBytes.sublist(0, 32);
      final pubkey = keyBytes.sublist(32);
      expect(pubkey.length, equals(32),
          reason: 'Last 32 bytes must be Ed25519 public key');
      expect(seed.length, equals(32));

      final key = K4SecretKey(keyBytes);
      expect(key.toString(), equals(expectString(vector, 'paserk')));

      final decoded = K4SecretKey.fromString(expectString(vector, 'paserk'));
      expect(decoded.rawBytes, equals(keyBytes));
    });

    test('k4.public encoding/decoding', () {
      final vector = k4TestVectors['k4.public']!;
      final keyBytes = hexToBytes(expectString(vector, 'public'));

      final key = K4PublicKey(keyBytes);
      expect(key.toString(), equals(expectString(vector, 'paserk')));

      expect(key.rawBytes.length, equals(32),
          reason: 'Ed25519 public key should be 32 bytes');

      final decoded = K4PublicKey.fromString(expectString(vector, 'paserk'));
      expect(decoded.rawBytes, equals(keyBytes));
    });

    test('k4.local-wrap wrapping/unwrapping', () {
      final vector = k4TestVectors['k4.local-wrap']!;
      final keyBytes = hexToBytes(expectString(vector, 'unwrapped'));
      final wrappingBytes = hexToBytes(expectString(vector, 'wrapping'));

      expect(keyBytes.length, equals(32),
          reason: 'k4.local-wrap unwrapped key must be 32 bytes');

      final originalKey = K4LocalKey(keyBytes);
      final wrappingKey = K4LocalKey(wrappingBytes);

      final wrappedFromVector =
          K4LocalWrap.unwrap(expectString(vector, 'paserk'), wrappingKey);
      expect(wrappedFromVector.rawBytes, equals(originalKey.rawBytes));

      expect(wrappedFromVector.rawBytes.length, equals(32),
          reason: 'k4.local-wrap unwrapped key must be 32 bytes after unwrap');

      final wrapped = K4LocalWrap.wrap(originalKey, wrappingKey);
      expect(wrapped.toString(), contains('k4.local-wrap.pie.'),
          reason: 'Should use standard pie wrapping protocol');

      final unwrapped = K4LocalWrap.unwrap(wrapped.toString(), wrappingKey);
      expect(unwrapped.rawBytes, equals(originalKey.rawBytes));

      final wrongKey = K4LocalKey(Uint8List(32));
      expect(
        () => K4LocalWrap.unwrap(wrapped.toString(), wrongKey),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('k4.secret-wrap wrapping/unwrapping', () {
      final vector = k4TestVectors['k4.secret-wrap']!;
      final keyBytes = hexToBytes(expectString(vector, 'unwrapped'));
      final wrappingBytes = hexToBytes(expectString(vector, 'wrapping'));

      expect(keyBytes.length, equals(64),
          reason: 'k4.secret-wrap unwrapped key must be 64 bytes');

      final originalKey = K4SecretKey(keyBytes);
      final wrappingKey = K4LocalKey(wrappingBytes);

      final wrappedFromVector =
          K4SecretWrap.unwrap(expectString(vector, 'paserk'), wrappingKey);
      expect(wrappedFromVector.rawBytes, equals(originalKey.rawBytes));

      expect(wrappedFromVector.rawBytes.length, equals(64),
          reason: 'k4.secret-wrap unwrapped key must be 64 bytes after unwrap');

      final wrapped = K4SecretWrap.wrap(originalKey, wrappingKey);
      expect(wrapped.toString(), contains('k4.secret-wrap.pie.'),
          reason: 'Should use standard pie wrapping protocol');

      final unwrapped = K4SecretWrap.unwrap(wrapped.toString(), wrappingKey);
      expect(unwrapped.rawBytes, equals(originalKey.rawBytes));

      final wrongKey = K4LocalKey(Uint8List(32));
      expect(
        () => K4SecretWrap.unwrap(wrapped.toString(), wrongKey),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('k4.local-pw wrapping/unwrapping', () async {
      final vector = k4TestVectors['k4.local-pw']!;
      final keyBytes = hexToBytes(expectString(vector, 'unwrapped'));
      final password = expectString(vector, 'passwordHex');

      final originalKey = K4LocalKey(keyBytes);

      final unwrapped =
          await K4LocalPw.unwrap(expectString(vector, 'paserk'), password);
      expect(unwrapped.rawBytes, equals(originalKey.rawBytes));

      final wrapped = await K4LocalPw.wrap(
        originalKey,
        password,
        memoryCost: vector['memlimit'] as int,
        timeCost: vector['opslimit'] as int,
      );
      final roundTrip = await K4LocalPw.unwrap(wrapped.toString(), password);
      expect(roundTrip.rawBytes, equals(originalKey.rawBytes));

      expect(
        () => K4LocalPw.unwrap(wrapped.toString(), 'wrong-password'),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('k4.secret-pw wrapping/unwrapping', () async {
      final vector = k4TestVectors['k4.secret-pw']!;
      final keyBytes = hexToBytes(expectString(vector, 'unwrapped'));
      final password = expectString(vector, 'passwordHex');

      final originalKey = K4SecretKey(keyBytes);

      final unwrapped =
          await K4SecretPw.unwrap(expectString(vector, 'paserk'), password);
      expect(unwrapped.rawBytes, equals(originalKey.rawBytes));

      final wrapped = await K4SecretPw.wrap(
        originalKey,
        password,
        memoryCost: vector['memlimit'] as int,
        timeCost: vector['opslimit'] as int,
      );
      final roundTrip = await K4SecretPw.unwrap(wrapped.toString(), password);
      expect(roundTrip.rawBytes, equals(originalKey.rawBytes));

      expect(
        () => K4SecretPw.unwrap(wrapped.toString(), 'wrong-password'),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('k4.seal sealing/unsealing', () async {
      final vector = k4TestVectors['k4.seal']!;
      final localKey = K4LocalKey(hexToBytes(expectString(vector, 'localKey')));
      final publicKey = K4PublicKey(hexToBytes(expectString(vector, 'public')));
      final secretKey = K4SecretKey(hexToBytes(expectString(vector, 'secret')));

      final unsealed =
          await K4Seal.unseal(expectString(vector, 'paserk'), secretKey);
      expect(unsealed.rawBytes, equals(localKey.rawBytes));

      final sealed = await K4Seal.seal(localKey, publicKey);
      final roundTrip = await K4Seal.unseal(sealed.toString(), secretKey);
      expect(roundTrip.rawBytes, equals(localKey.rawBytes));
    });

    test('k4.lid generation and comparison', () {
      final vector = k4TestVectors['k4.lid']!;
      final key = K4LocalKey.fromString(expectString(vector, 'key'));

      final lid = K4Lid.fromKey(key);
      expect(lid.toString(), equals(expectString(vector, 'paserk')));

      final lid2 = K4Lid.fromString(expectString(vector, 'paserk'));
      expect(lid, equals(lid2));
    });

    test('k4.pid generation and comparison', () {
      final vector = k4TestVectors['k4.pid']!;
      final key = K4PublicKey.fromString(expectString(vector, 'key'));

      final pid = K4Pid.fromKey(key);
      expect(pid.toString(), equals(expectString(vector, 'paserk')));

      final pid2 = K4Pid.fromString(expectString(vector, 'paserk'));
      expect(pid, equals(pid2));
    });

    test('k4.sid generation and comparison', () {
      final vector = k4TestVectors['k4.sid']!;
      final key = K4SecretKey.fromString(expectString(vector, 'key'));

      final sid = K4Sid.fromKey(key);
      expect(sid.toString(), equals(expectString(vector, 'paserk')));

      final sid2 = K4Sid.fromString(expectString(vector, 'paserk'));
      expect(sid, equals(sid2));
    });

    test('Cross-verification between public and secret keys', () async {
      final secretVector = k4TestVectors['k4.secret']!;
      final publicVector = k4TestVectors['k4.public']!;

      final secretKey =
          K4SecretKey.fromString(expectString(secretVector, 'paserk'));
      expect(secretKey.rawBytes.length, equals(64),
          reason: 'Ed25519 secret key must be 64 bytes');

      final derivedPublicKey = await K4PublicKey.fromSecretKey(secretKey);
      expect(derivedPublicKey.rawBytes.length, equals(32),
          reason: 'Ed25519 public key must be 32 bytes');

      expect(derivedPublicKey.toString(),
          equals(expectString(publicVector, 'paserk')));
    });

    test('Invalid key lengths', () {
      expect(
        () => K4LocalKey(Uint8List(31)),
        throwsArgumentError,
      );

      expect(
        () => K4SecretKey(Uint8List(63)),
        throwsArgumentError,
      );

      expect(
        () => K4PublicKey(Uint8List(31)),
        throwsArgumentError,
      );
    });
  });
}
