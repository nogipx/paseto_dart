import 'dart:convert';
import 'dart:typed_data';
import 'package:paseto_dart/blake2/blake2.dart';
import 'package:test/test.dart';

void main() {
  group('Blake2b PASETO Tests', () {
    test('PASETO v4 key derivation', () {
      // Симулируем ключ из 32 байт и 24-байтный nonce
      final key = Uint8List.fromList(List.generate(32, (index) => index));
      final nonce =
          Uint8List.fromList(List.generate(24, (index) => index + 100));

      // 1. Генерируем ключ шифрования и nonce
      // BLAKE2b(output=64bytes, key, 'paseto-encryption-key' || nonce)
      final encKeyDomain = utf8.encode('paseto-encryption-key');
      final encInput = Uint8List(encKeyDomain.length + nonce.length);
      encInput.setAll(0, encKeyDomain);
      encInput.setAll(encKeyDomain.length, nonce);

      // Используем нашу модифицированную библиотеку Blake2b
      // с поддержкой 64-байтного вывода для одного вызова
      final blake2bEnc = Blake2b(
        key: key,
        digestLength: 64, // 512 бит = 64 байта
      );

      blake2bEnc.update(encInput);
      final output = blake2bEnc.digest();

      // Разделяем 64-байтный вывод на нужные части
      final encryptionKey =
          output.sublist(0, 32); // 32 байта для ключа шифрования
      final counterNonce = output.sublist(32, 56); // 24 байта для nonce

      // 2. Генерируем ключ аутентификации (Ak)
      // BLAKE2b(output=32bytes, key, 'paseto-auth-key-for-aead' || nonce)
      final authKeyDomain = utf8.encode('paseto-auth-key-for-aead');
      final authInput = Uint8List(authKeyDomain.length + nonce.length);
      authInput.setAll(0, authKeyDomain);
      authInput.setAll(authKeyDomain.length, nonce);

      // Вычисляем ключ аутентификации с помощью Blake2b
      final blake2bAuth = Blake2b(
        key: key,
        digestLength: 32, // 256 бит = 32 байта
      );

      blake2bAuth.update(authInput);
      final authKeyData = blake2bAuth.digest();

      // Проверки
      expect(encryptionKey.length, equals(32));
      expect(counterNonce.length, equals(24));
      expect(authKeyData.length, equals(32));

      // Проверяем, что все ключи имеют ненулевые значения
      expect(ByteUtils.bytesToHex(encryptionKey), isNot(equals('0' * 64)));
      expect(ByteUtils.bytesToHex(counterNonce), isNot(equals('0' * 48)));
      expect(ByteUtils.bytesToHex(authKeyData), isNot(equals('0' * 64)));

      // Проверяем детерминированность - повторный вызов должен дать тот же результат
      final blake2bEnc2 = Blake2b(
        key: key,
        digestLength: 64,
      );

      blake2bEnc2.update(encInput);
      final output2 = blake2bEnc2.digest();

      expect(output, equals(output2));
    });

    test('MAC calculation with Pre-Authentication Encoding', () {
      // Параметры для тестирования
      final authKey =
          Uint8List.fromList(List.generate(32, (index) => index + 10));
      final headerBytes = utf8.encode('v4.local');
      final nonceBytes =
          Uint8List.fromList(List.generate(24, (index) => index + 50));
      final cipherText =
          Uint8List.fromList(List.generate(100, (index) => index + 150));
      final footer = utf8.encode('{"kid":"example"}');

      // Реализация Pre-Authentication Encoding (PAE)
      List<int> pae(List<List<int>> pieces) {
        final count = pieces.length;
        final countBytes = ByteUtils.le64(count);

        var totalSize = 8; // 8 байт для count
        for (final piece in pieces) {
          totalSize += 8; // 8 байт для длины каждого piece
          totalSize += piece.length; // длина самого piece
        }

        final result = Uint8List(totalSize);
        var offset = 0;

        // Записываем количество элементов
        for (var i = 0; i < 8; i++) {
          result[offset++] = countBytes[i];
        }

        // Для каждого элемента записываем его длину и затем сам элемент
        for (final piece in pieces) {
          final lengthBytes = ByteUtils.le64(piece.length);

          // Записываем длину элемента в формате LE64
          for (var i = 0; i < 8; i++) {
            result[offset++] = lengthBytes[i];
          }

          // Записываем данные самого элемента
          for (var i = 0; i < piece.length; i++) {
            result[offset++] = piece[i];
          }
        }

        return result;
      }

      // Реализуем PAE для наших данных
      final preAuth = pae([
        headerBytes, // h - заголовок
        nonceBytes, // n - nonce
        cipherText, // c - шифротекст
        footer, // f - футер
        <int>[], // i - implicit assertion (пустой)
      ]);

      // Вычисляем BLAKE2b-MAC
      final blake2bMac = Blake2b(
        key: authKey,
        digestLength: 32, // 256 бит
      );

      blake2bMac.update(Uint8List.fromList(preAuth));
      final macBytes = blake2bMac.digest();

      // Проверяем результат
      expect(macBytes.length, equals(32));
      expect(ByteUtils.bytesToHex(macBytes).length,
          equals(64)); // 32 байта = 64 hex символа

      // Проверяем детерминированность - повторный вызов должен дать тот же результат
      final blake2bMac2 = Blake2b(
        key: authKey,
        digestLength: 32,
      );

      blake2bMac2.update(Uint8List.fromList(preAuth));
      final macBytes2 = blake2bMac2.digest();

      expect(macBytes, equals(macBytes2));
    });
  });
}
