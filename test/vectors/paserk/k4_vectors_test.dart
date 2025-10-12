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

String _passwordValue(String raw) => raw;

void main() {
  final vectors = PaserkVectors.loadK4();

  group('PASERK k4 official vectors', () {
    group('k4.local', () {
      for (final vector in vectors.byType('k4.local')) {
        test(vector.name, () {
          final encoded = vector.requireString('paserk');

          if (vector.expectFail) {
            expect(() => K4LocalKey.fromString(encoded), throwsA(anything));
            return;
          }

          final keyBytes = hexToUint8List(vector.requireString('key'));
          final key = K4LocalKey(keyBytes);
          expect(key.toString(), encoded);
          expect(K4LocalKey.fromString(encoded).rawBytes, equals(keyBytes));
        });
      }
    });

    group('k4.secret', () {
      for (final vector in vectors.byType('k4.secret')) {
        test(vector.name, () {
          final paserk = vector.optionalString('paserk');
          final keyHex = vector.optionalString('key');

          if (vector.expectFail) {
            if (paserk != null) {
              expect(() => K4SecretKey.fromString(paserk), throwsA(anything));
            }
            if (keyHex != null) {
              expect(() => K4SecretKey.fromHex(keyHex), throwsA(anything));
            }
            return;
          }

          final key = K4SecretKey.fromHex(vector.requireString('key'));
          expect(
            uint8ListToHex(key.seed),
            equals(vector.requireString('secret-key-seed')),
          );
          expect(
            uint8ListToHex(key.publicKeyBytes),
            equals(vector.requireString('public-key')),
          );
          expect(key.toString(), equals(paserk));
          expect(
              K4SecretKey.fromString(paserk!).rawBytes, equals(key.rawBytes));
        });
      }
    });

    group('k4.public', () {
      for (final vector in vectors.byType('k4.public')) {
        test(vector.name, () {
          final keyHex = vector.optionalString('key');
          final paserk = vector.optionalString('paserk');

          if (vector.expectFail) {
            if (paserk != null) {
              expect(() => K4PublicKey.fromString(paserk), throwsA(anything));
            }
            if (keyHex != null) {
              expect(
                  () => K4PublicKey(hexToUint8List(keyHex)), throwsA(anything));
            }
            return;
          }

          final keyBytes = hexToUint8List(vector.requireString('key'));
          final key = K4PublicKey(keyBytes);
          expect(key.toString(), equals(paserk));
          expect(K4PublicKey.fromString(paserk!).rawBytes, equals(keyBytes));
        });
      }
    });

    group('k4.local-wrap.pie', () {
      for (final vector in vectors.byType('k4.local-wrap.pie')) {
        test(vector.name, () {
          final wrapping =
              K4LocalKey(hexToUint8List(vector.requireString('wrapping-key')));
          final paserk = vector.requireString('paserk');

          if (vector.expectFail) {
            expect(
                () => K4LocalWrap.unwrap(paserk, wrapping), throwsA(anything));
            return;
          }

          final unwrapped = K4LocalWrap.unwrap(paserk, wrapping);
          expect(
            uint8ListToHex(unwrapped.rawBytes),
            equals(vector.requireString('unwrapped')),
          );
        });
      }
    });

    group('k4.secret-wrap.pie', () {
      for (final vector in vectors.byType('k4.secret-wrap.pie')) {
        test(vector.name, () {
          final wrapping =
              K4LocalKey(hexToUint8List(vector.requireString('wrapping-key')));
          final paserk = vector.requireString('paserk');

          if (vector.expectFail) {
            expect(
                () => K4SecretWrap.unwrap(paserk, wrapping), throwsA(anything));
            return;
          }

          final unwrapped = K4SecretWrap.unwrap(paserk, wrapping);
          expect(
            uint8ListToHex(unwrapped.rawBytes),
            equals(vector.requireString('unwrapped')),
          );
        });
      }
    });

    group('k4.local-pw', () {
      for (final vector in vectors.byType('k4.local-pw')) {
        test(vector.name, () async {
          final password = _passwordValue(vector.requireString('password'));
          final paserk = vector.requireString('paserk');

          if (vector.expectFail) {
            await expectLater(
              K4LocalPw.unwrap(paserk, password),
              throwsA(anything),
            );
            return;
          }

          final key = await K4LocalPw.unwrap(paserk, password);
          expect(
            uint8ListToHex(key.rawBytes),
            equals(vector.requireString('unwrapped')),
          );
        });
      }
    });

    group('k4.secret-pw', () {
      for (final vector in vectors.byType('k4.secret-pw')) {
        test(vector.name, () async {
          final password = _passwordValue(vector.requireString('password'));
          final paserk = vector.requireString('paserk');

          if (vector.expectFail) {
            await expectLater(
              K4SecretPw.unwrap(paserk, password),
              throwsA(anything),
            );
            return;
          }

          final key = await K4SecretPw.unwrap(paserk, password);
          expect(
            uint8ListToHex(key.rawBytes),
            equals(vector.requireString('unwrapped')),
          );
        });
      }
    });

    group('k4.seal', () {
      for (final vector in vectors.byType('k4.seal')) {
        test(vector.name, () async {
          final secret = K4SecretKey(
              hexToUint8List(vector.requireString('sealing-secret-key')));
          final paserk = vector.requireString('paserk');

          if (vector.expectFail) {
            await expectLater(
              K4Seal.unseal(paserk, secret),
              throwsA(anything),
            );
            return;
          }

          final key = await K4Seal.unseal(paserk, secret);
          expect(
            uint8ListToHex(key.rawBytes),
            equals(vector.requireString('unsealed')),
          );
        });
      }
    });

    group('k4.lid', () {
      for (final vector in vectors.byType('k4.lid')) {
        test(vector.name, () {
          final keyHex = vector.optionalString('key');
          final paserk = vector.optionalString('paserk');

          if (vector.expectFail) {
            if (keyHex != null) {
              expect(
                  () => K4LocalKey(hexToUint8List(keyHex)), throwsA(anything));
            }
            if (paserk != null) {
              expect(() => K4Lid.fromString(paserk), throwsA(anything));
            }
            return;
          }

          final key = K4LocalKey(hexToUint8List(vector.requireString('key')));
          final identifier = K4Lid.fromKey(key);
          expect(identifier.toString(), equals(paserk));
          expect(
              K4Lid.fromString(paserk!).rawBytes, equals(identifier.rawBytes));
        });
      }
    });

    group('k4.pid', () {
      for (final vector in vectors.byType('k4.pid')) {
        test(vector.name, () {
          final keyHex = vector.optionalString('key');
          final paserk = vector.optionalString('paserk');

          if (vector.expectFail) {
            if (keyHex != null) {
              expect(
                  () => K4PublicKey(hexToUint8List(keyHex)), throwsA(anything));
            }
            if (paserk != null) {
              expect(() => K4Pid.fromString(paserk), throwsA(anything));
            }
            return;
          }

          final key = K4PublicKey(hexToUint8List(vector.requireString('key')));
          final identifier = K4Pid.fromKey(key);
          expect(identifier.toString(), equals(paserk));
          expect(
              K4Pid.fromString(paserk!).rawBytes, equals(identifier.rawBytes));
        });
      }
    });

    group('k4.sid', () {
      for (final vector in vectors.byType('k4.sid')) {
        test(vector.name, () {
          final keyHex = vector.optionalString('key');
          final paserk = vector.optionalString('paserk');

          if (vector.expectFail) {
            if (keyHex != null) {
              expect(() => K4SecretKey.fromHex(keyHex), throwsA(anything));
            }
            if (paserk != null) {
              expect(() => K4Sid.fromString(paserk), throwsA(anything));
            }
            return;
          }

          final key = K4SecretKey.fromHex(vector.requireString('key'));
          final identifier = K4Sid.fromKey(key);
          expect(identifier.toString(), equals(paserk));
          expect(
              K4Sid.fromString(paserk!).rawBytes, equals(identifier.rawBytes));
        });
      }
    });
  });
}
