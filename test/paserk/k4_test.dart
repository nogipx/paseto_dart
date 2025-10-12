import 'dart:convert';
import 'dart:typed_data';

import 'package:paseto_dart/paserk/k4_lid.dart';
import 'package:paseto_dart/paserk/k4_local.dart';
import 'package:paseto_dart/paserk/k4_local_pw.dart';
import 'package:paseto_dart/paserk/k4_local_wrap.dart';
import 'package:paseto_dart/paserk/k4_pid.dart';
import 'package:paseto_dart/paserk/k4_public.dart';
import 'package:paseto_dart/paserk/k4_seal.dart';
import 'package:paseto_dart/paserk/k4_secret.dart';
import 'package:paseto_dart/paserk/k4_secret_pw.dart';
import 'package:paseto_dart/paserk/k4_secret_wrap.dart';
import 'package:paseto_dart/paserk/k4_sid.dart';
import 'package:test/test.dart';

import 'test_vectors.dart';

Uint8List hexToBytes(String hex) {
  final cleaned = hex.replaceAll(RegExp(r'\s'), '');
  final result = Uint8List(cleaned.length ~/ 2);
  for (var i = 0; i < cleaned.length; i += 2) {
    result[i ~/ 2] = int.parse(cleaned.substring(i, i + 2), radix: 16);
  }
  return result;
}

String bytesToHex(List<int> bytes) {
  final buffer = StringBuffer();
  for (final byte in bytes) {
    buffer.write(byte.toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
}

String expectString(Map<String, Object> vector, String key) {
  final value = vector[key];
  expect(value, isA<String>(), reason: 'Expected "$key" to be a String');
  return value as String;
}

String passwordFromHex(String hex) {
  return utf8.decode(hexToBytes(hex));
}

void main() {
  group('PASERK v4 official vectors', () {
    group('k4.local', () {
      final vector = k4TestVectors['k4.local']!;

      test('round trips official value', () {
        final keyBytes = hexToBytes(expectString(vector, 'key'));
        final encoded = expectString(vector, 'paserk');

        final key = K4LocalKey(keyBytes);
        expect(key.toString(), equals(encoded));

        final decoded = K4LocalKey.fromString(encoded);
        expect(decoded.rawBytes, equals(keyBytes));
      });
    });

    group('k4.secret', () {
      final vector = k4TestVectors['k4.secret']!;

      test('round trips official value', () {
        final keyBytes = hexToBytes(expectString(vector, 'secret'));
        final encoded = expectString(vector, 'paserk');

        final key = K4SecretKey(keyBytes);
        expect(key.toString(), equals(encoded));
        expect(bytesToHex(key.rawBytes), equals(expectString(vector, 'secret')));

        final decoded = K4SecretKey.fromString(encoded);
        expect(decoded.rawBytes, equals(keyBytes));
      });
    });

    group('k4.public', () {
      final vector = k4TestVectors['k4.public']!;

      test('round trips official value', () {
        final keyBytes = hexToBytes(expectString(vector, 'public'));
        final encoded = expectString(vector, 'paserk');

        final key = K4PublicKey(keyBytes);
        expect(key.toString(), equals(encoded));

        final decoded = K4PublicKey.fromString(encoded);
        expect(decoded.rawBytes, equals(keyBytes));
      });
    });

    group('k4.local-wrap', () {
      final vector = k4TestVectors['k4.local-wrap']!;

      test('unwraps official wrapped key', () {
        final wrapping = K4LocalKey(hexToBytes(expectString(vector, 'wrapping')));
        final unwrapped = K4LocalWrap.unwrap(expectString(vector, 'paserk'), wrapping);

        expect(bytesToHex(unwrapped.rawBytes), equals(expectString(vector, 'unwrapped')));
      });

      test('rejects wrong wrapping key', () {
        final wrapping = K4LocalKey(Uint8List(32));
        expect(
          () => K4LocalWrap.unwrap(expectString(vector, 'paserk'), wrapping),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('round trips with generated wrap', () {
        final wrapping = K4LocalKey(hexToBytes(expectString(vector, 'wrapping')));
        final original = K4LocalKey(hexToBytes(expectString(vector, 'unwrapped')));

        final wrapped = K4LocalWrap.wrap(original, wrapping);
        final roundTrip = K4LocalWrap.unwrap(wrapped.toString(), wrapping);
        expect(roundTrip.rawBytes, equals(original.rawBytes));
      });
    });

    group('k4.secret-wrap', () {
      final vector = k4TestVectors['k4.secret-wrap']!;

      test('unwraps official wrapped key', () {
        final wrapping = K4LocalKey(hexToBytes(expectString(vector, 'wrapping')));
        final unwrapped = K4SecretWrap.unwrap(expectString(vector, 'paserk'), wrapping);

        expect(bytesToHex(unwrapped.rawBytes), equals(expectString(vector, 'unwrapped')));
      });

      test('rejects wrong wrapping key', () {
        final wrapping = K4LocalKey(Uint8List(32));
        expect(
          () => K4SecretWrap.unwrap(expectString(vector, 'paserk'), wrapping),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('round trips with generated wrap', () {
        final wrapping = K4LocalKey(hexToBytes(expectString(vector, 'wrapping')));
        final original = K4SecretKey(hexToBytes(expectString(vector, 'unwrapped')));

        final wrapped = K4SecretWrap.wrap(original, wrapping);
        final roundTrip = K4SecretWrap.unwrap(wrapped.toString(), wrapping);
        expect(roundTrip.rawBytes, equals(original.rawBytes));
      });
    });

    group('k4.local-pw', () {
      final vector = k4TestVectors['k4.local-pw']!;

      test('unwraps official password wrapped key', () async {
        final password = passwordFromHex(expectString(vector, 'passwordHex'));
        final unwrapped = await K4LocalPw.unwrap(
          expectString(vector, 'paserk'),
          password,
        );

        expect(bytesToHex(unwrapped.rawBytes), equals(expectString(vector, 'unwrapped')));
      });

      test('round trips with provided parameters', () async {
        final password = passwordFromHex(expectString(vector, 'passwordHex'));
        final original = K4LocalKey(hexToBytes(expectString(vector, 'unwrapped')));

        final wrapped = await K4LocalPw.wrap(
          original,
          password,
          memoryCost: vector['memlimit'] as int,
          timeCost: vector['opslimit'] as int,
        );

        final roundTrip = await K4LocalPw.unwrap(wrapped.toString(), password);
        expect(roundTrip.rawBytes, equals(original.rawBytes));
      });
    });

    group('k4.secret-pw', () {
      final vector = k4TestVectors['k4.secret-pw']!;

      test('unwraps official password wrapped key', () async {
        final password = passwordFromHex(expectString(vector, 'passwordHex'));
        final unwrapped = await K4SecretPw.unwrap(
          expectString(vector, 'paserk'),
          password,
        );

        expect(bytesToHex(unwrapped.rawBytes), equals(expectString(vector, 'unwrapped')));
      });

      test('round trips with provided parameters', () async {
        final password = passwordFromHex(expectString(vector, 'passwordHex'));
        final original = K4SecretKey(hexToBytes(expectString(vector, 'unwrapped')));

        final wrapped = await K4SecretPw.wrap(
          original,
          password,
          memoryCost: vector['memlimit'] as int,
          timeCost: vector['opslimit'] as int,
        );

        final roundTrip = await K4SecretPw.unwrap(wrapped.toString(), password);
        expect(roundTrip.rawBytes, equals(original.rawBytes));
      });
    });

    group('k4.seal', () {
      final vector = k4TestVectors['k4.seal']!;

      test('unseals official sealed key', () async {
        final secret = K4SecretKey(hexToBytes(expectString(vector, 'secret')));
        final unsealed = await K4Seal.unseal(
          expectString(vector, 'paserk'),
          secret,
        );

        expect(bytesToHex(unsealed.rawBytes), equals(expectString(vector, 'localKey')));
      });

      test('round trips sealed key using provided public key', () async {
        final secret = K4SecretKey(hexToBytes(expectString(vector, 'secret')));
        final public = K4PublicKey(hexToBytes(expectString(vector, 'public')));
        final original = K4LocalKey(hexToBytes(expectString(vector, 'localKey')));

        final sealed = await K4Seal.seal(original, public);
        final roundTrip = await K4Seal.unseal(sealed.toString(), secret);
        expect(roundTrip.rawBytes, equals(original.rawBytes));
      });
    });

    group('k4.lid', () {
      final vector = k4TestVectors['k4.lid']!;

      test('derives deterministic identifier', () {
        final key = K4LocalKey.fromString(expectString(vector, 'key'));
        final lid = K4Lid.fromKey(key);
        expect(lid.toString(), equals(expectString(vector, 'paserk')));

        final parsed = K4Lid.fromString(expectString(vector, 'paserk'));
        expect(parsed.rawBytes, equals(lid.rawBytes));
      });
    });

    group('k4.pid', () {
      final vector = k4TestVectors['k4.pid']!;

      test('derives deterministic identifier', () async {
        final key = K4PublicKey.fromString(expectString(vector, 'key'));
        final pid = K4Pid.fromKey(key);
        expect(pid.toString(), equals(expectString(vector, 'paserk')));

        final parsed = K4Pid.fromString(expectString(vector, 'paserk'));
        expect(parsed.rawBytes, equals(pid.rawBytes));
      });
    });

    group('k4.sid', () {
      final vector = k4TestVectors['k4.sid']!;

      test('derives deterministic identifier', () {
        final key = K4SecretKey.fromString(expectString(vector, 'key'));
        final sid = K4Sid.fromKey(key);
        expect(sid.toString(), equals(expectString(vector, 'paserk')));

        final parsed = K4Sid.fromString(expectString(vector, 'paserk'));
        expect(parsed.rawBytes, equals(sid.rawBytes));
      });
    });
  });
}
