import 'dart:convert';
import 'dart:io';

import 'package:paseto_dart/paseto_dart.dart';
import 'package:test/test.dart';

void main() {
  final pythonSkipReason = _detectPythonPaseto();

  group('Python PASERK interoperability', () {
    test('Dart-generated token decrypts in python-paseto', () async {
      final key = K4LocalKey.generate();
      final paserk = key.encode();
      final secretKey = SecretKey(key.rawBytes);
      final claims = {
        'sub': 'dart-user',
        'message': 'interop from dart',
        'counter': 7,
      };
      final package = Package(content: utf8.encode(jsonEncode(claims)));
      final encryptedPayload = await LocalV4.encrypt(
        package,
        secretKey: secretKey,
      );
      final token = Token(
        header: LocalV4.header,
        payload: encryptedPayload,
        footer: null,
      );
      final tokenString = token.toTokenString;

      const pythonScript = r'''
import json
import sys
from paseto.protocol import version4

paserk = sys.argv[1]
token = sys.argv[2]

parts = paserk.split('.')
if len(parts) >= 3:
    padding = '=' * ((4 - len(parts[-1]) % 4) % 4)
    parts[-1] = parts[-1] + padding
    paserk = '.'.join(parts)

key = paserk.encode('utf-8')
payload = version4.decrypt(token.encode('utf-8'), key)
sys.stdout.write(payload.decode('utf-8'))
''';

      final result = await Process.run('python3', [
        '-c',
        pythonScript,
        paserk,
        tokenString,
      ]);

      expect(
        result.exitCode,
        0,
        reason: 'python-paseto decrypt failed: ${result.stderr}',
      );

      final decoded = jsonDecode(result.stdout.trim()) as Map<String, dynamic>;
      expect(decoded, equals(claims));
    }, skip: pythonSkipReason);

    test('python-paseto generated token decrypts in Dart', () async {
      final key = K4LocalKey.generate();
      final paserk = key.encode();
      final secretKey = SecretKey(key.rawBytes);
      final claims = {
        'sub': 'python-user',
        'message': 'interop from python',
        'counter': 11,
      };
      final jsonPayload = jsonEncode(claims);

      const pythonScript = r'''
import sys
from paseto.protocol import version4

paserk = sys.argv[1]
content = sys.argv[2].encode('utf-8')

parts = paserk.split('.')
if len(parts) >= 3:
    padding = '=' * ((4 - len(parts[-1]) % 4) % 4)
    parts[-1] = parts[-1] + padding
    paserk = '.'.join(parts)

key = paserk.encode('utf-8')
token = version4.encrypt(content, key)
sys.stdout.write(token.decode('utf-8'))
''';

      final result = await Process.run('python3', [
        '-c',
        pythonScript,
        paserk,
        jsonPayload,
      ]);

      expect(
        result.exitCode,
        0,
        reason: 'python-paseto encrypt failed: ${result.stderr}',
      );

      final pythonToken = result.stdout.trim();
      final parsedToken = await Token.fromString(pythonToken);
      final decrypted = await LocalV4.decrypt(
        parsedToken,
        secretKey: secretKey,
      );
      final decoded =
          jsonDecode(utf8.decode(decrypted.content)) as Map<String, dynamic>;
      expect(decoded, equals(claims));
    }, skip: pythonSkipReason);
  });
}

String? _detectPythonPaseto() {
  try {
    final result = Process.runSync('python3', [
      '-c',
      'import base64, paseto; from paseto.protocol import version4',
    ]);
    if (result.exitCode == 0) {
      return null;
    }
    final output = '${result.stdout}${result.stderr}'.trim();
    return output.isEmpty ? 'python-paseto dependency not available' : output;
  } catch (error) {
    return 'python3 not available: $error';
  }
}
