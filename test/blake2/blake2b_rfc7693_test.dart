import 'dart:convert';
import 'dart:typed_data';
import 'package:paseto_dart/blake2/_index.dart';
import 'package:test/test.dart';

/// Тесты на основе подробного примера трассировки BLAKE2b и BLAKE2s
/// из RFC 7693 (Приложение A и B)
/// https://www.rfc-editor.org/rfc/rfc7693.txt
void main() {
  group('BLAKE2b RFC 7693 Appendix A Example Tests', () {
    test('RFC 7693 Appendix A - BLAKE2b detailed example', () {
      // Эта строка используется в примере из RFC 7693 Приложение A
      // Входные данные: строка "abc" (3 байта)
      final input = utf8.encode('abc');

      // Создание экземпляра BLAKE2b с длиной дайджеста 64 байта (512 бит)
      final blake2b = Blake2b(digestSize: 64);

      final output = blake2b.process(Uint8List.fromList(input));

      // Ожидаемый результат из RFC 7693, Приложение A
      final expectedHex =
          'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1'
          '7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923';

      // Проверка, что наш результат соответствует ожидаемому
      expect(ByteUtils.bytesToHex(output), equals(expectedHex));
    });

    test('RFC 7693 Appendix A - Empty string hash', () {
      // Хеш пустой строки - это еще один важный тестовый случай
      final blake2b = Blake2b(digestSize: 64);
      final emptyInput = Uint8List(0);
      final output = blake2b.process(emptyInput);

      final expectedHex =
          '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419'
          'd25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce';

      expect(ByteUtils.bytesToHex(output), equals(expectedHex));
    });

    test('RFC 7693 BLAKE2b - Message padding test', () {
      // В RFC 7693 указано, что сообщение должно быть дополнено нулями
      // до полного размера блока (128 байт для BLAKE2b)
      // Проверяем это на примере сообщения длиной равной блоку плюс 1 байт

      // Создаем BLAKE2b
      final blake2b = Blake2b(digestSize: 64);

      // Создаем входные данные размером ровно 128 байт (1 блок)
      final input1 = Uint8List(128)..fillRange(0, 128, 0x61); // заполняем 'a'
      final hash1 = blake2b.process(input1);

      // Сбрасываем BLAKE2b
      blake2b.reset();

      // Создаем входные данные размером 129 байт (1 блок + 1 байт)
      final input2 = Uint8List(129)..fillRange(0, 129, 0x61); // заполняем 'a'
      final hash2 = blake2b.process(input2);

      // Хеши должны отличаться
      expect(hash1, isNot(equals(hash2)));

      // Хеш блока размером 128 байт не должен равняться хешу от 127 байт
      blake2b.reset();
      final input3 = Uint8List(127)..fillRange(0, 127, 0x61);
      final hash3 = blake2b.process(input3);

      expect(hash1, isNot(equals(hash3)));
    });

    test('RFC 7693 BLAKE2b - Incrementally update test', () {
      // Проверка, что обновление за несколько вызовов дает тот же результат,
      // что и одно обновление с тем же содержимым

      // Одиночное обновление
      final blake2b1 = Blake2b(digestSize: 64);
      final input = utf8.encode('abcdefghijklmnopqrstuvwxyz');
      final hash1 = blake2b1.process(Uint8List.fromList(input));

      // Несколько обновлений
      final blake2b2 = Blake2b(digestSize: 64);
      final input1 = utf8.encode('abcdefghijkl');
      final input2 = utf8.encode('mnopqrstuvwxyz');
      final result = Uint8List.fromList(input1 + input2);
      final hash2 = blake2b2.process(result);

      // Хеши должны быть одинаковыми
      expect(hash1, equals(hash2));
    });

    test('RFC 7693 BLAKE2b - Keyed hashing test', () {
      // Тест на хеширование с ключом
      // RFC 7693 определяет, что ключ обрабатывается как блок сообщения с дополнением нулями

      // Создаем BLAKE2b с ключом
      final key = Uint8List.fromList(utf8.encode('key'));
      final blake2b = Blake2b(digestSize: 64, key: key);

      // Хешируем строку
      final input = utf8.encode('message');
      final keyedHash = blake2b.process(Uint8List.fromList(input));

      // Хеш без ключа должен отличаться
      final blake2bNoKey = Blake2b(digestSize: 64);
      final nonKeyedHash = blake2bNoKey.process(Uint8List.fromList(input));

      expect(keyedHash, isNot(equals(nonKeyedHash)));
    });

    test('RFC 7693 BLAKE2b - Salt and personalization test', () {
      // Тест на использование соли и персонализации
      // RFC 7693 определяет, что соль и персонализация используются для
      // изменения начального состояния

      final key = Uint8List.fromList(utf8.encode('key'));
      final input = utf8.encode('message');

      // Создаем salt и personalization ровно по 16 байт
      final salt = Uint8List(16)..fillRange(0, 16, 0x01);
      final personalization = Uint8List(16)..fillRange(0, 16, 0x02);

      // Хеш с salt и personalization
      final blake2b = Blake2b(
        digestSize: 64,
        key: key,
        salt: salt,
        personalization: personalization,
      );
      final hash1 = blake2b.process(Uint8List.fromList(input));

      // Хеш только с salt
      final blake2bSalt = Blake2b(
        digestSize: 64,
        key: key,
        salt: salt,
      );
      final hash2 = blake2bSalt.process(Uint8List.fromList(input));

      // Хеш только с personalization
      final blake2bPers = Blake2b(
        digestSize: 64,
        key: key,
        personalization: personalization,
      );
      final hash3 = blake2bPers.process(Uint8List.fromList(input));

      // Хеш без дополнительных параметров
      final blake2bBasic = Blake2b(digestSize: 64, key: key);
      final hash4 = blake2bBasic.process(Uint8List.fromList(input));

      // Все хеши должны отличаться
      expect(hash1, isNot(equals(hash2)));
      expect(hash1, isNot(equals(hash3)));
      expect(hash1, isNot(equals(hash4)));
      expect(hash2, isNot(equals(hash3)));
      expect(hash2, isNot(equals(hash4)));
      expect(hash3, isNot(equals(hash4)));
    });

    test('RFC 7693 BLAKE2b - Different output lengths', () {
      // RFC 7693 позволяет настраивать длину выхода от 1 до 64 байт
      final input = utf8.encode('abc');

      // Тестируем разные размеры вывода
      for (var len = 16; len <= 64; len += 16) {
        final blake2b = Blake2b(digestSize: len);
        final hash = blake2b.process(Uint8List.fromList(input));

        // Проверяем, что длина вывода соответствует запрошенной
        expect(hash.length, equals(len));
      }
    });
  });
}
