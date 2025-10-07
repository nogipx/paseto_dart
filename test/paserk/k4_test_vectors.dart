import 'dart:typed_data';

import 'package:paseto_dart/paserk/k4_lid.dart';
import 'package:paseto_dart/paserk/k4_local.dart';
import 'package:paseto_dart/paserk/k4_local_wrap.dart';
import 'package:paseto_dart/paserk/k4_pid.dart';
import 'package:paseto_dart/paserk/k4_public.dart';
import 'package:paseto_dart/paserk/k4_secret.dart';
import 'package:paseto_dart/paserk/k4_secret_wrap.dart';
import 'package:paseto_dart/paserk/k4_sid.dart';
import 'package:test/test.dart';

void main() {
  group('PASERK Test Vectors', () {
    test('k4.local test vector', () {
      final testKey = 'k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8';
      final key = K4LocalKey.fromString(testKey);
      expect(key.toString(), equals(testKey));
    });

    test('k4.public test vector', () {
      final testKey = 'k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI';
      final key = K4PublicKey.fromString(testKey);
      expect(key.toString(), equals(testKey));
    });

    test('k4.secret test vector', () {
      final testKey =
          'k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3QeuduuvAR8A_1wYE4AcfCYfhayy3VyJcEfAEFdDiCxog';
      final key = K4SecretKey.fromString(testKey);
      expect(key.toString(), equals(testKey));
    });

    test('k4.local-wrap test', () {
      final localKey = K4LocalKey.fromString(
          'k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8');
      final wrappingKey =
          K4LocalKey(Uint8List.fromList(List.generate(32, (i) => i)));

      final wrapped = K4LocalWrap.wrap(localKey, wrappingKey);
      expect(wrapped.toString(), startsWith('k4.local-wrap.'));

      final unwrapped = K4LocalWrap.unwrap(wrapped.toString(), wrappingKey);
      expect(unwrapped.toString(), equals(localKey.toString()));
    });

    test('k4.secret-wrap test', () {
      final secretKey = K4SecretKey.fromString(
          'k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3QeuduuvAR8A_1wYE4AcfCYfhayy3VyJcEfAEFdDiCxog');
      final wrappingKey =
          K4LocalKey(Uint8List.fromList(List.generate(32, (i) => 255 - i)));

      final wrapped = K4SecretWrap.wrap(secretKey, wrappingKey);
      expect(wrapped.toString(), startsWith('k4.secret-wrap.'));

      final unwrapped = K4SecretWrap.unwrap(wrapped.toString(), wrappingKey);
      expect(unwrapped.toString(), equals(secretKey.toString()));
    });

    test('k4.lid test', () {
      final localKey = K4LocalKey.fromString(
          'k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8');
      final lid = K4Lid.fromKey(localKey);
      expect(lid.toString(), startsWith('k4.lid.'));

      final lid2 = K4Lid.fromKey(localKey);
      expect(lid, equals(lid2));
    });

    test('k4.pid test', () async {
      final secretKey = K4SecretKey.fromString(
          'k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3QeuduuvAR8A_1wYE4AcfCYfhayy3VyJcEfAEFdDiCxog');
      final publicKey = await K4PublicKey.fromSecretKey(secretKey);
      final pid = K4Pid.fromKey(publicKey);
      expect(pid.toString(), startsWith('k4.pid.'));

      final pid2 = K4Pid.fromKey(publicKey);
      expect(pid, equals(pid2));
    });

    test('k4.sid test', () {
      final secretKey = K4SecretKey.fromString(
          'k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3QeuduuvAR8A_1wYE4AcfCYfhayy3VyJcEfAEFdDiCxog');
      final sid = K4Sid.fromKey(secretKey);
      expect(sid.toString(), startsWith('k4.sid.'));

      final sid2 = K4Sid.fromKey(secretKey);
      expect(sid, equals(sid2));
    });
  });
}
