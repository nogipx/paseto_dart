import 'dart:async';

import 'package:test/test.dart';
import 'package:paseto_dart/paseto_dart.dart';
import 'test_helpers.dart';

void main() {
  group('Тесты производительности', () {
    test('многократное шифрование/расшифрование токенов с одним ключом', () async {
      // Arrange
      final secretKey = await TestHelpers.generateSecretKey(32);
      const int iterations = 50; // Меньшее число для быстрых тестов

      // Act - измеряем время шифрования
      final stopwatch1 = Stopwatch()..start();
      final tokens = <Token>[];

      for (int i = 0; i < iterations; i++) {
        final message = await Message.encryptString(
          'Сообщение $i',
          version: Version.v4,
          secretKey: secretKey,
        );
        tokens.add(message.toToken);
      }

      final encryptionTime = stopwatch1.elapsedMilliseconds;

      // Act - измеряем время расшифрования
      final stopwatch2 = Stopwatch()..start();
      final decrypted = <String>[];

      for (int i = 0; i < iterations; i++) {
        final message = await tokens[i].decryptLocalMessage(
          secretKey: secretKey,
        );
        decrypted.add(message.stringContent ?? '');
      }

      final decryptionTime = stopwatch2.elapsedMilliseconds;

      // Assert
      // Проверяем корректность расшифровки
      for (int i = 0; i < iterations; i++) {
        expect(decrypted[i], equals('Сообщение $i'));
      }

      // Выводим результаты производительности
      print('Шифрование $iterations токенов: $encryptionTime мс');
      print('Расшифрование $iterations токенов: $decryptionTime мс');
      print('Среднее время шифрования: ${encryptionTime / iterations} мс на токен');
      print('Среднее время расшифрования: ${decryptionTime / iterations} мс на токен');
    });

    test('шифрование больших данных', () async {
      // Arrange
      final secretKey = await TestHelpers.generateSecretKey(32);
      final largeData = 'A' * 10000; // 10KB данных

      // Act
      final stopwatch = Stopwatch()..start();
      final message = await Message.encryptString(
        largeData,
        version: Version.v4,
        secretKey: secretKey,
      );

      final token = message.toToken;
      final decrypted = await token.decryptLocalMessage(secretKey: secretKey);
      final elapsed = stopwatch.elapsedMilliseconds;

      // Assert
      expect(decrypted.stringContent ?? '', equals(largeData));
      print('Шифрование и расшифрование 10KB данных: $elapsed мс');
    });

    test('параллельное шифрование и расшифровка', () async {
      // Arrange
      final secretKey = await TestHelpers.generateSecretKey(32);
      const int parallelOperations = 20;

      // Act
      final stopwatch = Stopwatch()..start();
      final futures = <Future<bool>>[];

      for (int i = 0; i < parallelOperations; i++) {
        futures.add(Future(() async {
          final payload = 'Параллельное сообщение $i';
          final message = await Message.encryptString(
            payload,
            version: Version.v4,
            secretKey: secretKey,
          );
          final token = message.toToken;
          final decrypted = await token.decryptLocalMessage(secretKey: secretKey);
          return decrypted.stringContent == payload;
        }));
      }

      final results = await Future.wait(futures);
      final elapsed = stopwatch.elapsedMilliseconds;

      // Assert
      expect(results.every((result) => result), isTrue);
      print('Параллельное шифрование/расшифрование $parallelOperations операций: $elapsed мс');
      print('Среднее время: ${elapsed / parallelOperations} мс на операцию');
    });

    test('сравнение производительности v2 и v4', () async {
      // Arrange
      final secretKey = await TestHelpers.generateSecretKey(32);
      const int iterations = 30;
      final testData = 'Тестовые данные для сравнения версий';

      // Act - v2
      final stopwatchV2 = Stopwatch()..start();
      for (int i = 0; i < iterations; i++) {
        final message = await Message.encryptString(
          testData,
          version: Version.v2,
          secretKey: secretKey,
        );
        final token = message.toToken;
        await token.decryptLocalMessage(secretKey: secretKey);
      }
      final elapsedV2 = stopwatchV2.elapsedMilliseconds;

      // Act - v4
      final stopwatchV4 = Stopwatch()..start();
      for (int i = 0; i < iterations; i++) {
        final message = await Message.encryptString(
          testData,
          version: Version.v4,
          secretKey: secretKey,
        );
        final token = message.toToken;
        await token.decryptLocalMessage(secretKey: secretKey);
      }
      final elapsedV4 = stopwatchV4.elapsedMilliseconds;

      // Assert - только выводим результаты
      print('Время для V2 ($iterations операций): $elapsedV2 мс');
      print('Время для V4 ($iterations операций): $elapsedV4 мс');
      print('Соотношение V4/V2: ${elapsedV4 / elapsedV2}');
    });
  });
}
