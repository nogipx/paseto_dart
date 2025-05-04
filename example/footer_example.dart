// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'dart:convert';
import 'dart:typed_data';
import 'package:paseto_dart/paseto_dart.dart';

/// Пример использования футера в PASETO токенах
///
/// Футеры могут использоваться для хранения метаданных, таких как:
/// - Идентификатор ключа (kid)
/// - Информация о приложении
/// - Любые другие метаданные, которые не требуют шифрования или подписи
Future<void> main() async {
  await _localTokenWithFooter();
  print('\n=== === === === === === === === === === === === ===\n');
  await _publicTokenWithFooter();
}

/// Пример с v4.local токеном и футером
Future<void> _localTokenWithFooter() async {
  print('🔐 ПРИМЕР: v4.local токен с футером');

  // Шаг 1: Создаем секретный ключ
  print('🔑 Генерация секретного ключа...');
  final secretKey = SecretKey(Uint8List.fromList(List.generate(32, (i) => i)));

  // Шаг 2: Подготавливаем данные для шифрования
  final sensitiveData = {
    'userId': 12345,
    'email': 'user@example.com',
    'exp': DateTime.now().add(Duration(hours: 1)).millisecondsSinceEpoch ~/ 1000
  };
  print('📦 Данные для шифрования: $sensitiveData');

  // Шаг 3: Создаем данные для футера (метаданные)
  final footerData = {
    'kid': 'key-1', // Идентификатор ключа
    'app': 'example-app', // Название приложения
    'issued_at': DateTime.now().toIso8601String()
  };
  print('🏷️ Данные футера: $footerData');

  // Шаг 4: Создаем пакет с данными и футером
  final package = Package(
    content: utf8.encode(jsonEncode(sensitiveData)),
    footer: utf8.encode(jsonEncode(footerData)),
  );

  // Шаг 5: Шифруем с помощью LocalV4
  print('🔒 Шифрование данных...');
  final encryptedPayload = await LocalV4.encrypt(
    package,
    secretKey: secretKey,
  );

  // Шаг 6: Создаем токен с футером
  final token = Token(
    header: LocalV4.header,
    payload: encryptedPayload,
    footer: utf8.encode(jsonEncode(footerData)),
  );

  // Получаем строковое представление токена для передачи
  final tokenString = token.toTokenString;
  print('🔒 Зашифрованный токен с футером: $tokenString');

  // Шаг 7: Распаковываем и проверяем токен (обычно на другой стороне)
  print('\n🔓 Проверка токена...');

  // Из строки получаем объект токена
  final receivedToken = await Token.fromString(tokenString);
  print('✅ Токен успешно распознан');

  // Сначала прочитаем футер (он не зашифрован)
  if (receivedToken.footer != null) {
    final parsedFooter = jsonDecode(utf8.decode(receivedToken.footer!));
    print('🏷️ Прочитан футер: $parsedFooter');

    // Проверяем идентификатор ключа
    final keyId = parsedFooter['kid'];
    print('🔑 Идентификатор ключа: $keyId');

    // В реальном приложении здесь можно было бы получить нужный ключ по его ID
    // final actualKey = getKeyById(keyId);
  } else {
    print('❌ Футер отсутствует');
    return;
  }

  // Дешифруем сообщение
  final decrypted = await receivedToken.decryptLocalMessage(
    secretKey: secretKey,
  );

  // Преобразуем расшифрованные данные из байтов в JSON
  try {
    final decodedPayload = jsonDecode(utf8.decode(decrypted.package.content));
    print('🔓 Расшифрованные данные: $decodedPayload');
  } catch (e) {
    print('❌ Ошибка при декодировании данных: $e');
    print('🔍 Расшифрованные байты: ${_bytesToHex(decrypted.package.content)}');
    print('🔍 Длина данных: ${decrypted.package.content.length}');
  }

  print('✅ Пример v4.local с футером успешно выполнен!');
}

/// Пример с v4.public токеном и футером
Future<void> _publicTokenWithFooter() async {
  print('🔏 ПРИМЕР: v4.public токен с футером');

  // Шаг 1: Создание ключевой пары Ed25519
  print('🔑 Генерация ключевой пары Ed25519...');
  final ed25519 = Ed25519();
  final keyPair = await ed25519.newKeyPair();
  final publicKey = await keyPair.extractPublicKey();

  // Шаг 2: Подготавливаем данные для подписи
  final userData = {
    'sub': 'user_12345',
    'name': 'Иван Иванов',
    'exp': DateTime.now().add(Duration(hours: 1)).millisecondsSinceEpoch ~/ 1000
  };
  print('📦 Данные для подписи: $userData');

  // Шаг 3: Создаем данные для футера (метаданные)
  final footerData = {
    'kid': 'public-key-1', // Идентификатор ключа
    'purpose': 'authentication', // Назначение токена
    'issued_at': DateTime.now().toIso8601String()
  };
  print('🏷️ Данные футера: $footerData');

  // Шаг 4: Создаем пакет с данными и футером
  final package = Package(
    content: utf8.encode(jsonEncode(userData)),
    footer: utf8.encode(jsonEncode(footerData)),
  );

  // Шаг 5: Подписываем данные с помощью PublicV4
  print('🔏 Подписываем данные...');
  final signedPayload = await PublicV4.sign(
    package,
    keyPair: keyPair,
  );

  // Шаг 6: Создаем токен с футером
  final token = Token(
    header: PublicV4.header,
    payload: signedPayload,
    footer: utf8.encode(jsonEncode(footerData)),
  );

  // Получаем строковое представление токена для передачи
  final tokenString = token.toTokenString;
  print('🔏 Подписанный токен с футером: $tokenString');

  // Шаг 7: Проверяем подпись и читаем футер
  print('\n✅ Проверка токена...');

  // Из строки получаем объект токена
  final receivedToken = await Token.fromString(tokenString);
  print('✅ Токен успешно распознан');

  // Сначала прочитаем футер (он доступен без проверки подписи)
  if (receivedToken.footer != null) {
    final parsedFooter = jsonDecode(utf8.decode(receivedToken.footer!));
    print('🏷️ Прочитан футер: $parsedFooter');

    // Проверяем идентификатор ключа
    final keyId = parsedFooter['kid'];
    print('🔑 Идентификатор ключа: $keyId');

    // В реальном приложении здесь можно было бы получить нужный ключ по его ID
    // final publicKey = getPublicKeyById(keyId);
  } else {
    print('❌ Футер отсутствует');
    return;
  }

  // Проверяем подпись
  final verified = await receivedToken.verifyPublicMessage(
    publicKey: publicKey,
  );

  // Если подпись верна, получаем данные из токена
  try {
    final decodedPayload = jsonDecode(utf8.decode(verified.package.content));
    print('✅ Подпись проверена успешно!');
    print('📦 Проверенные данные: $decodedPayload');
  } catch (e) {
    print('❌ Ошибка при декодировании данных: $e');
    print('🔍 Байты данных: ${_bytesToHex(verified.package.content)}');
    print('🔍 Длина данных: ${verified.package.content.length}');
  }

  print('✅ Пример v4.public с футером успешно выполнен!');
}

/// Вспомогательная функция для отображения байтов в шестнадцатеричном формате
String _bytesToHex(List<int> bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join('');
}
