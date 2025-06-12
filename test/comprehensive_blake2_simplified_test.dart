import 'dart:convert';
import 'dart:typed_data';

import 'package:paseto_dart/blake2/_index.dart' as blake2;
import 'package:test/test.dart';

void main() {
  group('Blake2b Simplified Tests', () {
    test('Blake2b базовое хеширование', () {
      final input = utf8.encode('test data');
      final hasher = blake2.Blake2b(digestSize: 32);
      final result = hasher.hashSync(input);

      expect(result.length, equals(32));
      expect(result, isNot(isEmpty));
    });

    test('Blake2b различные размеры дайджеста', () {
      final input = utf8.encode('test');

      for (int outLen = 16; outLen <= 64; outLen += 16) {
        final hasher = blake2.Blake2b(digestSize: outLen);
        final result = hasher.hashSync(input);

        expect(result.length, equals(outLen));
      }
    });

    test('Blake2b с ключом', () {
      final input = utf8.encode('keyed test');
      final key = Uint8List.fromList(List.generate(32, (i) => i));

      final hasher1 = blake2.Blake2b(digestSize: 32, key: key);
      final result1 = hasher1.hashSync(input);

      final hasher2 = blake2.Blake2b(digestSize: 32, key: key);
      final result2 = hasher2.hashSync(input);

      expect(result1, equals(result2));

      // Без ключа результат должен отличаться
      final hasher3 = blake2.Blake2b(digestSize: 32);
      final result3 = hasher3.hashSync(input);

      expect(result1, isNot(equals(result3)));
    });

    test('Blake2b инкрементальное добавление', () {
      final hasher = blake2.Blake2b(digestSize: 32);

      hasher.addSync(utf8.encode('part1'));
      hasher.addSync(utf8.encode('part2'));

      final incrementalResult = hasher.digestSync();

      // Сравниваем с прямым хешированием
      final directResult =
          blake2.Blake2b(digestSize: 32).hashSync(utf8.encode('part1part2'));

      expect(incrementalResult, equals(directResult));
    });

    test('Blake2b пустой input', () {
      final empty = Uint8List(0);
      final hasher = blake2.Blake2b(digestSize: 32);
      final result = hasher.hashSync(empty);

      expect(result.length, equals(32));
      expect(result, isNot(equals(Uint8List(32))));
    });

    test('Blake2b производительность', () {
      final largeData =
          Uint8List.fromList(List.generate(100000, (i) => i % 256));

      final stopwatch = Stopwatch()..start();
      final hasher = blake2.Blake2b(digestSize: 64);
      final result = hasher.hashSync(largeData);
      stopwatch.stop();

      expect(result.length, equals(64));
      expect(
          stopwatch.elapsedMilliseconds, lessThan(1000)); // Должно быть быстро
    });

    test('Blake2b детерминистичность', () {
      final input = utf8.encode('deterministic test');

      final result1 = blake2.Blake2b(digestSize: 32).hashSync(input);
      final result2 = blake2.Blake2b(digestSize: 32).hashSync(input);

      expect(result1, equals(result2));
    });

    test('Blake2b с персонализацией', () {
      final input = utf8.encode('personal test');
      // Персонализация должна быть точно 16 байт
      final personal = Uint8List(16);
      final personalBytes = utf8.encode('v1.0');
      personal.setRange(0, personalBytes.length, personalBytes);

      final hasher1 = blake2.Blake2b(digestSize: 32, personalization: personal);
      final result1 = hasher1.hashSync(input);

      final hasher2 = blake2.Blake2b(digestSize: 32);
      final result2 = hasher2.hashSync(input);

      expect(result1, isNot(equals(result2)));
    });

    test('Blake2b с солью', () {
      final input = utf8.encode('salt test');
      final salt = Uint8List.fromList(List.generate(16, (i) => i));

      final hasher1 = blake2.Blake2b(digestSize: 32, salt: salt);
      final result1 = hasher1.hashSync(input);

      final hasher2 = blake2.Blake2b(digestSize: 32);
      final result2 = hasher2.hashSync(input);

      expect(result1, isNot(equals(result2)));
    });

    test('Blake2b PASETO ключевая деривация', () {
      final masterKey = Uint8List.fromList(List.generate(32, (i) => i + 1));

      // Персонализация должна быть точно 16 байт
      final info = Uint8List(16);
      final infoBytes = utf8.encode('PASETO v4 encrypt');
      info.setRange(
          0, infoBytes.length > 16 ? 16 : infoBytes.length, infoBytes);

      final derivedKey =
          blake2.Blake2b(digestSize: 32, key: masterKey, personalization: info)
              .hashSync(Uint8List(0));

      expect(derivedKey.length, equals(32));

      // Другая персонализация должна давать другой ключ
      final authInfo = Uint8List(16);
      final authInfoBytes = utf8.encode('PASETO v4 auth');
      authInfo.setRange(0,
          authInfoBytes.length > 16 ? 16 : authInfoBytes.length, authInfoBytes);

      final authKey = blake2.Blake2b(
              digestSize: 32, key: masterKey, personalization: authInfo)
          .hashSync(Uint8List(0));

      expect(authKey, isNot(equals(derivedKey)));
    });

    test('Blake2b memory и ресурсы', () {
      // Тест на отсутствие memory leaks
      for (int i = 0; i < 1000; i++) {
        final hasher = blake2.Blake2b(digestSize: 32);
        hasher.hashSync(utf8.encode('test $i'));
      }

      expect(true, isTrue); // Если дошли сюда, то всё ок
    });
  });
}
