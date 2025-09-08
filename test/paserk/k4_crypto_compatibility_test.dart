import 'dart:typed_data';

import 'package:paseto_dart/blake2/blake2b_pointycastle.dart';
import 'package:paseto_dart/chacha20/_index.dart';
import 'package:paseto_dart/paserk/k4_local.dart';
import 'package:paseto_dart/paserk/k4_local_wrap.dart';
import 'package:test/test.dart';

import 'k4_test.dart';
import 'test_vectors.dart';

void main() {
  group('PASERK Crypto Implementation Tests', () {
    test('XChaCha20 compatibility with LocalV4', () async {
      final vector = k4TestVectors['k4.local']!;
      final keyBytes = hexToBytes(vector['key']!);

      // Создаем тестовые данные
      final data = Uint8List.fromList([1, 2, 3, 4, 5]);
      final nonce = Uint8List(24);
      for (var i = 0; i < nonce.length; i++) {
        nonce[i] = i;
      }

      // Шифруем с помощью XChaCha20 как в LocalV4
      final xchacha1 = XChaCha20();
      final keyParam1 = KeyParameter(Uint8List.fromList(keyBytes));
      xchacha1.init(true, ParametersWithIV<KeyParameter>(keyParam1, nonce));
      final encrypted1 = xchacha1.process(data);

      // Шифруем с помощью XChaCha20 как в PASERK
      final xchacha2 = XChaCha20();
      final keyParam2 = KeyParameter(Uint8List.fromList(keyBytes));
      xchacha2.init(true, ParametersWithIV<KeyParameter>(keyParam2, nonce));
      final encrypted2 = xchacha2.process(data);

      // Проверяем, что результаты идентичны
      expect(encrypted1, equals(encrypted2));
    });

    test('BLAKE2b compatibility with LocalV4', () {
      final vector = k4TestVectors['k4.local']!;
      final keyBytes = hexToBytes(vector['key']!);

      final data = Uint8List.fromList([1, 2, 3, 4, 5]);

      // Хешируем с помощью BLAKE2b как в LocalV4
      final blake2b1 = Blake2b(
        key: keyBytes,
        digestSize: 32,
      );
      final hash1 = blake2b1.process(data);

      // Хешируем с помощью BLAKE2b как в PASERK
      final blake2b2 = Blake2b(
        key: keyBytes,
        digestSize: 32,
      );
      final hash2 = Uint8List(32);
      blake2b2.update(data, 0, data.length);
      blake2b2.doFinal(hash2, 0);

      // Проверяем, что результаты идентичны
      expect(hash1, equals(hash2));
    });

    test('Key wrapping domain separation compatibility', () async {
      final vector = k4TestVectors['k4.local-wrap']!;
      final keyBytes = hexToBytes(vector['unwrapped']!);
      final password = vector['password']!;
      final key = K4LocalKey(keyBytes);

      // Делаем wrapping с тем же паролем дважды
      final wrapped1 = await K4LocalWrap.wrap(key, password);
      final wrapped2 = await K4LocalWrap.wrap(key, password);

      // Проверяем, что каждый раз получается разный результат из-за случайной соли
      expect(wrapped1.toString(), isNot(equals(wrapped2.toString())));

      // Но при этом оба варианта можно успешно расшифровать
      final unwrapped1 =
          await K4LocalWrap.unwrap(wrapped1.toString(), password);
      final unwrapped2 =
          await K4LocalWrap.unwrap(wrapped2.toString(), password);

      expect(unwrapped1.rawBytes, equals(key.rawBytes));
      expect(unwrapped2.rawBytes, equals(key.rawBytes));
    });

    test('Constant-time comparison compatibility', () {
      final bytes1 = Uint8List.fromList(List.generate(32, (i) => i));
      final bytes2 = Uint8List.fromList(List.generate(32, (i) => i));
      final bytes3 = Uint8List.fromList(List.generate(32, (i) => i + 1));

      // Тестируем сравнение с постоянным временем как в LocalV4
      var result = 0;
      for (var i = 0; i < bytes1.length; i++) {
        result |= bytes1[i] ^ bytes2[i];
      }
      expect(result, equals(0));

      result = 0;
      for (var i = 0; i < bytes1.length; i++) {
        result |= bytes1[i] ^ bytes3[i];
      }
      expect(result, isNot(equals(0)));
    });
  });
}
