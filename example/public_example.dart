// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'dart:convert';
import 'package:paseto_dart/paseto_dart.dart';

/// Пример подписи и проверки подписи с помощью PASETO v4.public
///
/// PASETO v4.public использует Ed25519 для создания и проверки подписей.
/// Этот режим подходит для авторизации и аутентификации, когда нужно проверить
/// подлинность данных без раскрытия секретного ключа.
Future<void> main() async {
  // Шаг 1: Создание ключевой пары Ed25519
  print('🔑 Генерация ключевой пары Ed25519...');
  final ed25519 = Ed25519();
  final keyPair = await ed25519.newKeyPair();
  final publicKey = await keyPair.extractPublicKey();

  final publicKeyBytes = publicKey.bytes;
  print('🔑 Публичный ключ (hex): ${_bytesToHex(publicKeyBytes)}');

  // Шаг 2: Подготавливаем данные для подписи (например, информация о пользователе)
  final userData = {
    'sub': 'user_12345',
    'name': 'Иван Иванов',
    'role': 'пользователь',
    'exp': DateTime.now().add(Duration(hours: 1)).millisecondsSinceEpoch ~/ 1000
  };
  print('📦 Данные для подписи: $userData');

  // Шаг 3: Создаем пакет с данными
  final package = Package(
    content: utf8.encode(jsonEncode(userData)),
  );

  // Шаг 4: Подписываем данные с помощью PublicV4
  print('🔏 Подписываем данные...');
  final signedPayload = await PublicV4.sign(
    package,
    keyPair: keyPair,
  );

  // Шаг 5: Создаем токен
  final token = Token(
    header: PublicV4.header,
    payload: signedPayload,
    footer: null,
  );

  // Получаем строковое представление токена для передачи
  final tokenString = token.toTokenString;
  print('🔏 Подписанный токен: $tokenString');

  // Шаг 6: Проверяем подпись (обычно выполняется на другой стороне)
  print('\n✅ Проверка подписи токена...');

  // Из строки получаем объект токена
  final receivedToken = await Token.fromString(tokenString);
  print('✅ Токен успешно распознан');

  // Проверяем, что это действительно токен v4.public
  if (receivedToken.header != PublicV4.header) {
    print('❌ Ошибка: Неверный формат токена');
    return;
  }
  print('✅ Проверка формата: действительно v4.public');

  // Проверяем подпись, используя публичный ключ
  try {
    final verified = await receivedToken.verifyPublicMessage(
      publicKey: publicKey,
    );

    // Если подпись верна, получаем данные из токена
    try {
      final decodedPayload = jsonDecode(utf8.decode(verified.package.content));
      print('✅ Подпись проверена успешно!');
      print('📦 Проверенные данные: $decodedPayload');

      // Проверяем срок действия
      final expiration = decodedPayload['exp'] as int;
      final currentTime = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      if (currentTime > expiration) {
        print('⚠️ Предупреждение: Токен просрочен');
      } else {
        print('✅ Токен действителен еще ${expiration - currentTime} секунд');
      }
    } catch (e) {
      print('❌ Ошибка при декодировании данных: $e');
      print('🔍 Байты данных: ${_bytesToHex(verified.package.content)}');
      print('🔍 Длина данных: ${verified.package.content.length}');
    }
  } catch (e) {
    print('❌ Ошибка проверки подписи: $e');
    return;
  }

  // Шаг 7: Демонстрация попытки подделки токена
  print('\n⚠️ Демонстрация защиты от подделки...');

  // Создадим другую ключевую пару, имитируя злоумышленника
  final attackerKeyPair = await ed25519.newKeyPair();
  final attackerPublicKey = await attackerKeyPair.extractPublicKey();

  try {
    // Пытаемся проверить с неправильным ключом
    await receivedToken.verifyPublicMessage(
      publicKey: attackerPublicKey,
    );
    print('❌ УЯЗВИМОСТЬ: Подпись проверена чужим ключом!');
  } catch (e) {
    // Ожидаемое поведение - должна быть ошибка проверки подписи
    print('✅ Защита работает: попытка проверки чужим ключом отклонена');
  }

  print('\n✅ Пример успешно выполнен!');
}

/// Вспомогательная функция для отображения байтов в шестнадцатеричном формате
String _bytesToHex(List<int> bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join('');
}
