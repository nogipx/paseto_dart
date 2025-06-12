import 'dart:convert';
import 'dart:typed_data';

import 'package:paseto_dart/paseto_dart.dart';

Future<void> main(List<String> args) async {
  await localExample();

  print('\n\n------------------------------------\n\n');

  await localExampleWithFooter();

  print('\n\n====================================\n\n');

  await publicExample();

  print('\n\n------------------------------------\n\n');

  await publicExampleWithFooter();
}

/// Пример подписи и проверки подписи с помощью PASETO v4.public
///
/// PASETO v4.public использует Ed25519 для создания и проверки подписей.
/// Этот режим подходит для авторизации и аутентификации, когда нужно проверить
/// подлинность данных без раскрытия секретного ключа.
Future<void> publicExample() async {
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
  print('✅ Проверка подписи токена...');

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
  print('⚠️ Демонстрация защиты от подделки...');

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

  print('✅ Пример успешно выполнен!');
}

/// Пример шифрования и дешифрования данных с помощью PASETO v4.local
///
/// PASETO v4.local использует XChaCha20 для шифрования и BLAKE2b для MAC.
/// Этот режим подходит для защиты чувствительных данных и безопасного
/// хранения информации, которая должна быть доступна только определенным сторонам.
Future<void> localExample() async {
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
  print('🔓 Дешифрование токена...');

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

  print('✅ Пример успешно выполнен!');
}

/// Пример с v4.local токеном и футером
Future<void> localExampleWithFooter() async {
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
  print('🔓 Проверка токена...');

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
Future<void> publicExampleWithFooter() async {
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
  print('✅ Проверка токена...');

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
