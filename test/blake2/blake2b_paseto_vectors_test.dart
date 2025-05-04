import 'dart:convert';
import 'dart:typed_data';
import 'package:paseto_dart/blake2/_index.dart';
import 'package:test/test.dart';

/// Тесты для проверки совместимости Blake2b с PASETO протоколом
/// PASETO использует BLAKE2b для ключей, MAC и других криптографических операций
void main() {
  group('BLAKE2b PASETO-specific test vectors', () {
    test('PASETO v4 key derivation', () {
      // PASETO v4 использует BLAKE2b для генерации ключей шифрования
      // Пример из спецификации PASETO v4 (если такая есть)

      // Тестовые данные
      final ikm = Uint8List.fromList(
          List.generate(32, (i) => i)); // Начальный ключевой материал
      final info = utf8.encode('paseto-encryption-key'); // Строка контекста

      // Функция BLAKE2b для генерации ключа
      final blake2b = Blake2b(digestSize: 64, key: ikm);
      final output = blake2b.process(Uint8List.fromList(info));

      // Разделяем вывод на ключ и nonce (в соответствии с PASETO v4)
      final encryptionKey = output.sublist(0, 32);
      final nonce = output.sublist(32, 56);

      // Вывод для отладки
      print('Encryption Key: ${ByteUtils.bytesToHex(encryptionKey)}');
      print('Nonce: ${ByteUtils.bytesToHex(nonce)}');

      // Проверяем, что вывод имеет правильную длину
      expect(encryptionKey.length, equals(32)); // 256 бит
      expect(nonce.length, equals(24)); // 192 бита
    });

    test('PASETO MAC calculation', () {
      // PASETO использует BLAKE2b для MAC (Message Authentication Code)

      // Настройки для теста
      final key = Uint8List.fromList(List.generate(32, (i) => i)); // MAC key
      final message = utf8.encode('This is a test message for PASETO MAC');

      // Расчет MAC
      final blake2b = Blake2b(digestSize: 32, key: key); // MAC длиной 32 байта
      final mac = blake2b.process(Uint8List.fromList(message));

      // Проверка длины MAC
      expect(mac.length, equals(32)); // 256 бит

      // Проверка детерминированности - один и тот же вход должен давать один и тот же MAC
      final blake2b2 = Blake2b(digestSize: 32, key: key);
      final mac2 = blake2b2.process(Uint8List.fromList(message));

      expect(ByteUtils.bytesToHex(mac), equals(ByteUtils.bytesToHex(mac2)));

      // Проверка, что изменение сообщения изменяет MAC
      final alteredMessage =
          utf8.encode('This is a MODIFIED message for PASETO MAC');
      final blake2b3 = Blake2b(digestSize: 32, key: key);
      final mac3 = blake2b3.process(Uint8List.fromList(alteredMessage));

      expect(
          ByteUtils.bytesToHex(mac), isNot(equals(ByteUtils.bytesToHex(mac3))));
    });

    test('PASETO token format compatibility', () {
      // Тест для проверки совместимости Blake2b с форматом токенов PASETO

      // Создаем имитацию локального токена v4
      final header = Uint8List.fromList(utf8.encode('v4.local.'));
      final payload = Uint8List.fromList(
          utf8.encode('{"data":"test","exp":"2022-01-01T00:00:00+00:00"}'));
      final footer = Uint8List.fromList(utf8.encode('{"kid":"test-key"}'));

      // Ключ для PASETO
      final key = Uint8List(32)..fillRange(0, 32, 0x42); // Заполняем 'B'

      // Вычисляем pre-auth (pre-authentication context)
      final preAuth = _concatBytes([
        Uint8List.fromList([0, 0, 0, 0, 0, 0, 0, 0]), // 64-битный литерал PAE
        Uint8List.fromList([0, 0, 0, 0, 0, 0, 0, 3]), // 3 элемента
        Uint8List.fromList([0, 0, 0, 0, 0, 0, 0, header.length]),
        header,
        Uint8List.fromList([0, 0, 0, 0, 0, 0, 0, payload.length]),
        payload,
        Uint8List.fromList([0, 0, 0, 0, 0, 0, 0, footer.length]),
        footer
      ]);

      // Вычисляем MAC с помощью Blake2b
      final blake2b = Blake2b(digestSize: 32, key: key);
      final mac = blake2b.process(preAuth);

      // Проверяем детерминизм MAC
      final blake2b2 = Blake2b(digestSize: 32, key: key);
      final mac2 = blake2b2.process(preAuth);

      expect(ByteUtils.bytesToHex(mac), equals(ByteUtils.bytesToHex(mac2)));

      // Проверяем что MAC зависит от ключа
      final altKey = Uint8List(32)..fillRange(0, 32, 0x43); // Другой ключ
      final blake2b3 = Blake2b(digestSize: 32, key: altKey);
      final mac3 = blake2b3.process(preAuth);

      expect(
          ByteUtils.bytesToHex(mac), isNot(equals(ByteUtils.bytesToHex(mac3))));
    });

    test('BLAKE2b performance with large data', () {
      // Этот тест проверяет производительность Blake2b с большими данными
      // Важно для PASETO, где могут обрабатываться большие токены

      // Создаем большой блок данных (1MB)
      final largeData = Uint8List(1024 * 1024)..fillRange(0, 1024 * 1024, 0xFF);

      // Хешируем данные с помощью Blake2b
      final blake2b = Blake2b(digestSize: 64);

      // Измеряем время выполнения
      final stopwatch = Stopwatch()..start();

      final hash = blake2b.process(largeData);

      stopwatch.stop();
      final elapsedMilliseconds = stopwatch.elapsedMilliseconds;

      // Печатаем время выполнения для информации
      print('BLAKE2b hashed 1MB in $elapsedMilliseconds ms');

      // Проверяем, что хеш имеет правильную длину
      expect(hash.length, equals(64)); // 512 бит

      // Здесь можно добавить конкретный проверки на производительность,
      // но они зависят от железа, поэтому обычно не включаются в тесты
    });
  });
}

/// Вспомогательный метод для конкатенации массива байтов
Uint8List _concatBytes(List<Uint8List> arrays) {
  // Вычисляем общую длину
  int totalLength = 0;
  for (final array in arrays) {
    totalLength += array.length;
  }

  // Создаем результирующий массив
  final result = Uint8List(totalLength);

  // Копируем данные
  int offset = 0;
  for (final array in arrays) {
    result.setRange(offset, offset + array.length, array);
    offset += array.length;
  }

  return result;
}
