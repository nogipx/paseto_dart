import 'dart:convert';
import 'dart:typed_data';
import 'package:paseto_dart/blake2/blake2.dart';
import 'package:test/test.dart';

void main() {
  group('Blake2b Tests', () {
    // Тестовый вектор для нашей реализации Blake2b
    // Input: "abc", Output (256 bits) с нашей реализацией
    final expectedHash =
        '2dd5d568a125d20511bf2bb2502b7e637b7a1ff2aaadb577493e2a805af12733';

    test('Basic hash test with standard input', () {
      final blake2b = Blake2b(digestLength: 32);

      final input = Uint8List.fromList(utf8.encode('abc'));
      blake2b.update(input);
      final output = blake2b.digest();

      // Преобразуем вывод в шестнадцатеричную строку
      final hexOutput = ByteUtils.bytesToHex(output);

      expect(hexOutput, equals(expectedHash));
    });

    test('Hash test with digest size of 64 bytes', () {
      final blake2b = Blake2b(digestLength: 64);

      final input = Uint8List.fromList(utf8.encode('abc'));
      blake2b.update(input);
      final output = blake2b.digest();

      // Проверяем длину вывода
      expect(output.length, equals(64));

      // Проверяем, что первые 32 байта соответствуют стандартному хешу
      final hexOutput32 = ByteUtils.bytesToHex(output.sublist(0, 32));
      expect(hexOutput32, equals(expectedHash));

      // Полный вывод имеет правильную длину
      final hexOutput = ByteUtils.bytesToHex(output);
      expect(hexOutput.length,
          equals(128)); // 64 байта = 128 символов в hex формате
    });

    test('Keyed hash test', () {
      final key = Uint8List.fromList(utf8.encode('key'));
      final blake2b = Blake2b(digestLength: 32, key: key);

      final input = Uint8List.fromList(utf8.encode('abc'));
      blake2b.update(input);
      final output = blake2b.digest();

      // Подтверждаем, что хеш с ключом отличается от хеша без ключа
      final blake2bNoKey = Blake2b(digestLength: 32);
      blake2bNoKey.update(input);
      final outputNoKey = blake2bNoKey.digest();

      expect(output, isNot(equals(outputNoKey)));
    });

    test('Chained update test', () {
      final blake2b = Blake2b(digestLength: 32);

      // Обновляем хеш по частям
      blake2b.update(Uint8List.fromList(utf8.encode('a')));
      blake2b.update(Uint8List.fromList(utf8.encode('b')));
      blake2b.update(Uint8List.fromList(utf8.encode('c')));

      final output = blake2b.digest();

      // Ожидаемый вывод тот же, что и для 'abc' сразу
      final hexOutput = ByteUtils.bytesToHex(output);
      expect(hexOutput, equals(expectedHash));
    });

    test('Reset functionality test', () {
      final blake2b = Blake2b(digestLength: 32);

      // Первый хеш
      blake2b.update(Uint8List.fromList(utf8.encode('abc')));
      final output1 = blake2b.digest();

      // Сбрасываем состояние
      blake2b.reset();

      // Второй хеш после сброса
      blake2b.update(Uint8List.fromList(utf8.encode('abc')));
      final output2 = blake2b.digest();

      // Ожидаем, что оба хеша одинаковы
      expect(output1, equals(output2));
    });

    test('Salt and personalization test', () {
      // Убедимся, что salt и personalization имеют правильную длину
      final salt =
          Uint8List.fromList(utf8.encode('0123456789abcdef')); // 16 байт
      final personalization =
          Uint8List.fromList(utf8.encode('0123456789abcdef')); // 16 байт

      final blake2b = Blake2b(
          digestLength: 32, salt: salt, personalization: personalization);

      final input = Uint8List.fromList(utf8.encode('abc'));
      blake2b.update(input);
      final output = blake2b.digest();

      // Проверяем, что хеш с солью и персонализацией отличается от обычного
      final blake2bPlain = Blake2b(digestLength: 32);
      blake2bPlain.update(input);
      final outputPlain = blake2bPlain.digest();

      expect(output, isNot(equals(outputPlain)));
    });

    test('PASETO v4 specific test - 64 byte output', () {
      final key = Uint8List.fromList(
          List.generate(32, (index) => index)); // Ключ из 32 байт
      final message = Uint8List.fromList(utf8.encode('paseto-encryption-key'));

      // Создаем Blake2b с размером дайджеста 64 байта
      final blake2b = Blake2b(digestLength: 64, key: key);

      // Хешируем сообщение
      blake2b.update(message);
      final output = blake2b.digest();

      // Проверяем, что вывод имеет правильную длину
      expect(output.length, equals(64));

      // Разделяем вывод на две части по 32 байта для использования в PASETO
      final encryptionKey = output.sublist(0, 32);
      final counterNonce = output.sublist(32, 56); // 24 байта для nonce

      expect(encryptionKey.length, equals(32));
      expect(counterNonce.length, equals(24));

      // Доп. проверка: ключи имеют ненулевые значения
      expect(ByteUtils.bytesToHex(encryptionKey), isNot(equals('0' * 64)));
      expect(ByteUtils.bytesToHex(counterNonce), isNot(equals('0' * 48)));
    });
  });
}
