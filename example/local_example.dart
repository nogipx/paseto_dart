// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'dart:convert';
import 'dart:typed_data';
import 'package:paseto_dart/paseto_dart.dart';

/// Пример шифрования и дешифрования данных с помощью PASETO v4.local
///
/// PASETO v4.local использует XChaCha20 для шифрования и BLAKE2b для MAC.
/// Этот режим подходит для защиты чувствительных данных и безопасного
/// хранения информации, которая должна быть доступна только определенным сторонам.
Future<void> main() async {
  // Шаг 1: Создаем секретный ключ (32 байта для v4.local)
  print('🔑 Генерация секретного ключа...');
  final secretKey = SecretKey(Uint8List.fromList(List.generate(32, (i) => i)));

  // Шаг 2: Подготавливаем данные для шифрования
  final sensitiveData = {
    'userId': 12345,
    'email': 'user@example.com',
    'role': 'admin',
    'exp': DateTime.now().add(Duration(hours: 1)).millisecondsSinceEpoch ~/ 1000
  };
  print('📦 Данные для шифрования: $sensitiveData');

  // Шаг 3: Создаем пакет с данными
  final package = Package(
    content: utf8.encode(jsonEncode(sensitiveData)),
  );

  // Шаг 4: Шифруем с помощью LocalV4
  print('🔒 Шифрование данных...');
  final encryptedPayload = await LocalV4.encrypt(
    package,
    secretKey: secretKey,
  );

  // Шаг 5: Создаем токен
  final token = Token(
    header: LocalV4.header,
    payload: encryptedPayload,
    footer: null,
  );

  // Получаем строковое представление токена для передачи
  final tokenString = token.toTokenString;
  print('🔒 Зашифрованный токен: $tokenString');

  // Шаг 6: Дешифруем токен (обычно выполняется на другой стороне)
  print('\n🔓 Дешифрование токена...');

  // Из строки получаем объект токена
  final receivedToken = await Token.fromString(tokenString);
  print('✅ Токен успешно распознан');

  // Проверяем, что это действительно токен v4.local
  if (receivedToken.header != LocalV4.header) {
    print('❌ Ошибка: Неверный формат токена');
    return;
  }
  print('✅ Проверка формата: действительно v4.local');

  // Дешифруем с использованием того же секретного ключа
  final decrypted = await receivedToken.decryptLocalMessage(
    secretKey: secretKey,
  );

  // Преобразуем расшифрованные данные из байтов в JSON
  try {
    final decodedPayload = jsonDecode(utf8.decode(decrypted.package.content));
    print('🔓 Расшифрованные данные: $decodedPayload');

    // Проверяем срок действия (exp)
    final expiration = decodedPayload['exp'] as int;
    final currentTime = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    if (currentTime > expiration) {
      print('⚠️ Предупреждение: Токен просрочен');
    } else {
      print('✅ Токен действителен еще ${expiration - currentTime} секунд');
    }
  } catch (e) {
    print('❌ Ошибка при декодировании данных: $e');
    print('🔍 Расшифрованные байты: ${_bytesToHex(decrypted.package.content)}');
    print('🔍 Длина данных: ${decrypted.package.content.length}');
  }

  print('\n✅ Пример успешно выполнен!');
}

/// Вспомогательная функция для отображения байтов в шестнадцатеричном формате
String _bytesToHex(List<int> bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join('');
}
