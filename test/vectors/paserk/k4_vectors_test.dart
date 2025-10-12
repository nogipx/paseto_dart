import 'dart:convert';

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

import '../../vectors.dart';

String _passwordFromHex(String hex) {
  return utf8.decode(hexToUint8List(hex));
}

void main() {
  late PaserkVectors vectors;

  setUpAll(() {
    vectors = PaserkVectors.loadK4();
  });

  group('PASERK k4 official vectors', () {
    for (final vector in vectors.byType('k4.local')) {
      test('round trips ${vector.name}', () {
        final keyBytes = hexToUint8List(vector.requireString('key'));
        final encoded = vector.requireString('paserk');

        final key = K4LocalKey(keyBytes);
        expect(key.toString(), equals(encoded));

        final parsed = K4LocalKey.fromString(encoded);
        expect(parsed.rawBytes, equals(keyBytes));
      });
    }

    for (final vector in vectors.byType('k4.secret')) {
      test('round trips ${vector.name}', () {
        final keyBytes = hexToUint8List(vector.requireString('secret'));
        final encoded = vector.requireString('paserk');

        final key = K4SecretKey(keyBytes);
        expect(key.toString(), equals(encoded));
        expect(uint8ListToHex(key.rawBytes), equals(vector.requireString('secret')));

        final parsed = K4SecretKey.fromString(encoded);
        expect(parsed.rawBytes, equals(keyBytes));
      });
    }

    for (final vector in vectors.byType('k4.public')) {
      test('round trips ${vector.name}', () {
        final keyBytes = hexToUint8List(vector.requireString('public'));
        final encoded = vector.requireString('paserk');

        final key = K4PublicKey(keyBytes);
        expect(key.toString(), equals(encoded));

        final parsed = K4PublicKey.fromString(encoded);
        expect(parsed.rawBytes, equals(keyBytes));
      });
    }

    for (final vector in vectors.byType('k4.local-wrap')) {
      test('unwraps ${vector.name}', () {
        final wrapping = K4LocalKey(hexToUint8List(vector.requireString('wrapping')));
        final unwrapped = K4LocalWrap.unwrap(vector.requireString('paserk'), wrapping);

        expect(uint8ListToHex(unwrapped.rawBytes), equals(vector.requireString('unwrapped')));
      });
    }

    for (final vector in vectors.byType('k4.secret-wrap')) {
      test('unwraps ${vector.name}', () {
        final wrapping = K4LocalKey(hexToUint8List(vector.requireString('wrapping')));
        final unwrapped = K4SecretWrap.unwrap(vector.requireString('paserk'), wrapping);

        expect(uint8ListToHex(unwrapped.rawBytes), equals(vector.requireString('unwrapped')));
      });
    }

    for (final vector in vectors.byType('k4.local-pw')) {
      test('unwraps ${vector.name}', () async {
        final password = _passwordFromHex(vector.requireString('passwordHex'));
        final key = await K4LocalPw.unwrap(vector.requireString('paserk'), password);

        expect(uint8ListToHex(key.rawBytes), equals(vector.requireString('unwrapped')));
      });
    }

    for (final vector in vectors.byType('k4.secret-pw')) {
      test('unwraps ${vector.name}', () async {
        final password = _passwordFromHex(vector.requireString('passwordHex'));
        final key = await K4SecretPw.unwrap(vector.requireString('paserk'), password);

        expect(uint8ListToHex(key.rawBytes), equals(vector.requireString('unwrapped')));
      });
    }

    for (final vector in vectors.byType('k4.seal')) {
      test('unseals ${vector.name}', () async {
        final secret = K4SecretKey(hexToUint8List(vector.requireString('secret')));
        final key = await K4Seal.unseal(vector.requireString('paserk'), secret);

        expect(uint8ListToHex(key.rawBytes), equals(vector.requireString('localKey')));
      });
    }

    for (final vector in vectors.byType('k4.lid')) {
      test('derives ${vector.name}', () {
        final key = K4LocalKey.fromString(vector.requireString('key'));
        final identifier = K4Lid.fromKey(key);

        expect(identifier.toString(), equals(vector.requireString('paserk')));

        final parsed = K4Lid.fromString(vector.requireString('paserk'));
        expect(parsed.rawBytes, equals(identifier.rawBytes));
      });
    }

    for (final vector in vectors.byType('k4.pid')) {
      test('derives ${vector.name}', () {
        final key = K4PublicKey.fromString(vector.requireString('key'));
        final identifier = K4Pid.fromKey(key);

        expect(identifier.toString(), equals(vector.requireString('paserk')));

        final parsed = K4Pid.fromString(vector.requireString('paserk'));
        expect(parsed.rawBytes, equals(identifier.rawBytes));
      });
    }

    for (final vector in vectors.byType('k4.sid')) {
      test('derives ${vector.name}', () {
        final key = K4SecretKey.fromString(vector.requireString('key'));
        final identifier = K4Sid.fromKey(key);

        expect(identifier.toString(), equals(vector.requireString('paserk')));

        final parsed = K4Sid.fromString(vector.requireString('paserk'));
        expect(parsed.rawBytes, equals(identifier.rawBytes));
      });
    }
  });
}
