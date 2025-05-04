// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'dart:convert';
import 'dart:typed_data';
import 'package:paseto_dart/chacha20/_index.dart';

/// Отладочный пример для проверки XChaCha20 напрямую
void main() {
  print('🔍 Отладка XChaCha20 шифрования/дешифрования');

  // 1. Создаем тестовые данные
  final plaintext = 'Это тестовое сообщение для шифрования';
  print('📄 Исходный текст: $plaintext');
  final plaintextBytes = utf8.encode(plaintext);

  // 2. Создаем ключ и случайный nonce
  final key =
      Uint8List.fromList(List.generate(32, (i) => i)); // 32-байтный ключ
  final nonce =
      Uint8List.fromList(List.generate(24, (i) => i + 100)); // 24-байтный nonce

  // 3. Инициализируем XChaCha20 для шифрования
  final xchacha = XChaCha20();
  final keyParam = KeyParameter(key);
  final params = ParametersWithIV<KeyParameter>(keyParam, nonce);

  print('🔑 Ключ: ${_bytesToHex(key)}');
  print('🔄 Nonce: ${_bytesToHex(nonce)}');

  // 4. Шифруем данные
  xchacha.init(true, params);
  final ciphertext = xchacha.process(Uint8List.fromList(plaintextBytes));
  print('🔒 Зашифрованный текст (hex): ${_bytesToHex(ciphertext)}');

  // 5. Инициализируем новый экземпляр XChaCha20 для дешифрования
  final xchachaDec = XChaCha20();
  xchachaDec.init(false, params);

  // 6. Дешифруем данные
  final decrypted = xchachaDec.process(ciphertext);
  print('🔓 Дешифрованный текст (bytes): ${_bytesToHex(decrypted)}');

  // 7. Проверяем, соответствуют ли дешифрованные данные исходным
  if (_bytesEqual(decrypted, Uint8List.fromList(plaintextBytes))) {
    print('✅ Успех! Дешифрованные данные совпадают с исходными');
    print('🔤 Дешифрованный текст: ${utf8.decode(decrypted)}');
  } else {
    print('❌ Ошибка: Дешифрованные данные не совпадают с исходными');
    printDifferences(decrypted, Uint8List.fromList(plaintextBytes));
  }

  // 8. Проверяем, правильно ли работает UTF-8 кодирование/декодирование
  try {
    final decodedText = utf8.decode(decrypted);
    print('✅ UTF-8 декодирование успешно: $decodedText');
  } catch (e) {
    print('❌ Ошибка UTF-8 декодирования: $e');
    print('📊 Причина: возможно, дешифрованные данные повреждены');
  }
}

/// Проверяет, равны ли два массива байтов
bool _bytesEqual(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// Выводит различия между ожидаемыми и фактическими данными
void printDifferences(List<int> actual, List<int> expected) {
  print('📊 Сравнение байтов:');
  print('📏 Длина ожидаемых данных: ${expected.length}');
  print('📏 Длина фактических данных: ${actual.length}');

  final minLength =
      actual.length < expected.length ? actual.length : expected.length;
  var diffCount = 0;

  print('🔍 Первые различия:');
  for (var i = 0; i < minLength; i++) {
    if (actual[i] != expected[i]) {
      print(
          '   Позиция $i: ожидалось ${expected[i]} (${expected[i].toRadixString(16)}), '
          'получено ${actual[i]} (${actual[i].toRadixString(16)})');
      diffCount++;
      if (diffCount >= 10) {
        print('   ... и ещё ${minLength - i - 1} различий');
        break;
      }
    }
  }
}

/// Вспомогательная функция для отображения байтов в шестнадцатеричном формате
String _bytesToHex(List<int> bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join('');
}
