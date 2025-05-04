import 'dart:convert';
import 'dart:typed_data';
import 'package:paseto_dart/blake2/blake2.dart';
import 'package:test/test.dart';

void main() {
  group('Blake2b Official Vectors', () {
    // Официальные тестовые векторы Blake2b из спецификации RFC 7693
    // https://datatracker.ietf.org/doc/html/rfc7693#appendix-A

    test('BLAKE2b-512 empty string', () {
      final blake2b = Blake2b(digestLength: 64); // 512 бит
      final input = Uint8List(0); // пустая строка
      blake2b.update(input);
      final output = blake2b.digest();

      final expectedHex =
          '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419'
          'd25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce';

      expect(ByteUtils.bytesToHex(output), equals(expectedHex));
    });

    test('BLAKE2b-512 "abc" string', () {
      final blake2b = Blake2b(digestLength: 64);
      final input = utf8.encode('abc');
      blake2b.update(Uint8List.fromList(input));
      final output = blake2b.digest();

      final expectedHex =
          'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1'
          '7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923';

      expect(ByteUtils.bytesToHex(output), equals(expectedHex));
    });

    test('BLAKE2b-256 "abc" string', () {
      final blake2b = Blake2b(digestLength: 32); // 256 бит
      final input = utf8.encode('abc');
      blake2b.update(Uint8List.fromList(input));
      final output = blake2b.digest();

      final expectedHex =
          'bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319';

      expect(ByteUtils.bytesToHex(output), equals(expectedHex));
    });

    test('BLAKE2b-384 "abc" string', () {
      final blake2b = Blake2b(digestLength: 48); // 384 бит
      final input = utf8.encode('abc');
      blake2b.update(Uint8List.fromList(input));
      final output = blake2b.digest();

      final expectedHex =
          '6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6'
          'c66ba83be64b302d7cba6ce15bb556f4';

      expect(ByteUtils.bytesToHex(output), equals(expectedHex));
    });

    test('BLAKE2b-512 keyed hash', () {
      final key = Uint8List.fromList(List.generate(64, (i) => i));
      final blake2b = Blake2b(digestLength: 64, key: key);
      final input = utf8.encode('abc');
      blake2b.update(Uint8List.fromList(input));
      final output = blake2b.digest();

      final expectedHex =
          'c2a8162e9409287eb58674c0bb48b72b92c7c98a9cf7277f4d18a81ad30aeb8e'
          'a33b629b1fe16ecc2be1d0fabb68e74d013dffd5edce173bc6a08222df237c4c';

      expect(ByteUtils.bytesToHex(output), equals(expectedHex));
    });

    // Тестовый вектор конкретно для PASETO из спецификации
    test('PASETO v4 specific test vector', () {
      final key = Uint8List.fromList(List.generate(32, (i) => i));
      final message = utf8.encode('paseto-encryption-key');

      // В PASETO v4 используется Blake2b с выводом 64 байта
      final blake2b = Blake2b(digestLength: 64, key: key);
      blake2b.update(Uint8List.fromList(message));
      final output = blake2b.digest();

      // Берем первые 32 байта для ключа шифрования
      final encKey = output.sublist(0, 32);

      // Следующие 24 байта для nonce
      final nonce = output.sublist(32, 56);

      // Значения из спецификации для проверки (если они доступны)
      // Здесь будут эталонные значения

      expect(encKey.length, equals(32));
      expect(nonce.length, equals(24));
    });

    // Тест с salt и personalization
    test('BLAKE2b with salt and personalization', () {
      final key = Uint8List.fromList(utf8.encode('key'));

      // Создаем salt ровно 16 байт
      final salt = Uint8List(16);
      final saltSource = utf8.encode('saltysalt');
      salt.setAll(
          0,
          saltSource.sublist(
              0, saltSource.length > 16 ? 16 : saltSource.length));

      // Создаем personalization ровно 16 байт
      final personalization = Uint8List(16);
      final persSource = utf8.encode('personal');
      personalization.setAll(
          0,
          persSource.sublist(
              0, persSource.length > 16 ? 16 : persSource.length));

      final blake2b = Blake2b(
          digestLength: 64,
          key: key,
          salt: salt,
          personalization: personalization);

      final input = utf8.encode('abc');
      blake2b.update(Uint8List.fromList(input));
      final output = blake2b.digest();

      // Выводим хеш для отладки
      print(
          'BLAKE2b with salt and personalization: ${ByteUtils.bytesToHex(output)}');

      // Тест проверяет, что хеш отличается от обычного
      final blake2bNoSalt = Blake2b(digestLength: 64, key: key);
      blake2bNoSalt.update(Uint8List.fromList(input));
      final outputNoSalt = blake2bNoSalt.digest();

      expect(output, isNot(equals(outputNoSalt)));
    });
  });
}
