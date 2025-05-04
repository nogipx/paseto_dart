// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:paseto_dart/blake2/_index.dart' as blake2lib;
import 'package:paseto_dart/models/_index.dart';
import 'package:paseto_dart/paseto_dart.dart';
import 'package:paseto_dart/chacha20/_index.dart';

/// Класс для вспомогательных данных ключей шифрования.
class _DerivedKeys {
  final List<int> encryptionKey;
  final List<int> counterNonce;
  final List<int> authKey;

  _DerivedKeys({
    required this.encryptionKey,
    required this.counterNonce,
    required this.authKey,
  });
}

/// Реализация локального режима PASETO версии 4 (v4.local).
///
/// Использует XChaCha20 для шифрования и BLAKE2b для MAC и генерации ключей.
/// Основано на спецификации PASETO v4: https://github.com/paseto-standard/paseto-spec
class LocalV4 {
  /// Заголовок для токенов v4.local
  static const header = Header(version: Version.v4, purpose: Purpose.local);

  /// Размер nonce в байтах
  static const nonceLength = 32;

  /// Размер MAC в байтах
  static const macLength = 32;

  /// Ключ должен быть 32 байта (256 бит)
  static const keyLength = 32;

  /// Префикс для генерации ключа шифрования
  static const _encryptionKeyDomain = 'paseto-encryption-key';

  /// Префикс для генерации ключа аутентификации
  static const _authKeyDomain = 'paseto-auth-key-for-aead';

  /// Шифрует пакет данных, создавая PASETO v4.local токен.
  static Future<Payload> encrypt(
    Package package, {
    required SecretKey secretKey,
    List<int>? implicit,
  }) async {
    // Получаем ключ для шифрования
    final keyBytes = await secretKey.extractBytes();

    // Проверяем размер ключа
    if (keyBytes.length != keyLength) {
      throw ArgumentError(
          'Ключ должен быть $keyLength байт, получено: ${keyBytes.length}');
    }

    // Генерируем случайный nonce (32 байта)
    final nonce = Uint8List(nonceLength);
    final random = Random.secure();
    for (var i = 0; i < nonceLength; i++) {
      nonce[i] = random.nextInt(256);
    }

    // 1. Генерируем ключи шифрования (Ek) и аутентификации (Ak)
    final encKeys = await _deriveKeys(keyBytes, nonce);
    final encryptionKey = encKeys.encryptionKey;
    final counterNonce = encKeys.counterNonce;
    final authKey = encKeys.authKey;

    // 2. Шифруем сообщение с помощью XChaCha20
    // Для PASETO v4.local мы используем первые 32 байта для ключа и следующие 24 как nonce, но
    // библиотека ожидает nonce размером 12 байт для Chacha20.poly1305Aead()
    final chacha20 = Chacha20.poly1305Aead();
    final secretBox = await chacha20.encrypt(
      package.content,
      secretKey: SecretKey(encryptionKey),
      nonce: Uint8List.fromList(
          counterNonce.sublist(0, 12)), // Используем первые 12 байт как nonce
      aad: Uint8List(
          0), // AAD не используется при шифровании (используется только при вычислении MAC)
    );

    // 3. Подготавливаем данные для аутентификации (PAE)
    final headerBytes = utf8.encode(header.toTokenString);
    final implicitBytes = implicit ?? <int>[];
    final footer = package.footer ?? <int>[];

    // 4. PAE(h, n, c, f, i)
    final preAuth = _pae([
      headerBytes, // h - заголовок
      nonce, // n - nonce
      secretBox.cipherText, // c - шифротекст
      footer, // f - футер (опциональный)
      implicitBytes, // i - implicit assertion (опциональный)
    ]);

    // 5. Вычисляем BLAKE2b-MAC с помощью ключа аутентификации
    final macBytes = _computeMac(preAuth, authKey);
    final mac = Mac(macBytes);

    // 6. Объединяем данные для токена
    final payload = PayloadLocal(
      nonce: Mac(nonce),
      secretBox: SecretBox(
        secretBox.cipherText,
        nonce: Uint8List.fromList(
            counterNonce.sublist(0, 12)), // Используем первые 12 байт nonce
        mac: mac,
      ),
      mac: mac,
    );

    return payload;
  }

  /// Дешифрует PASETO v4.local токен.
  static Future<Package> decrypt(
    Token token, {
    required SecretKey secretKey,
    List<int>? implicit,
  }) async {
    // Получаем ключ для дешифрования
    final keyBytes = await secretKey.extractBytes();

    // Проверяем размер ключа
    if (keyBytes.length != keyLength) {
      throw ArgumentError(
          'Ключ должен быть $keyLength байт, получено: ${keyBytes.length}');
    }

    // Проверяем, что токен соответствует v4.local
    if (token.header != header) {
      throw FormatException('Неверный заголовок токена для v4.local');
    }

    // Получаем payload и разбираем его составляющие
    final payload = token.payloadLocal;
    if (payload == null) {
      throw FormatException('Неверный формат токена для v4.local');
    }

    // Извлекаем nonce, cipherText и MAC
    final nonce = payload.nonce;
    if (nonce == null || nonce.bytes.length != nonceLength) {
      throw FormatException('Неверный формат nonce в токене v4.local');
    }

    final secretBox = payload.secretBox;
    if (secretBox == null) {
      throw FormatException('Шифротекст отсутствует в токене v4.local');
    }

    final mac = payload.mac;
    if (mac == null || mac.bytes.length != macLength) {
      throw FormatException('Неверный формат MAC в токене v4.local');
    }

    // Диагностическая информация
    print('Дешифрование токена:');
    print('  Nonce: ${_bytesToHex(nonce.bytes)}');
    print('  CipherText: ${_bytesToHex(secretBox.cipherText)}');
    print('  MAC from token: ${_bytesToHex(mac.bytes)}');
    print(
        '  Footer: ${token.footer != null ? _bytesToHex(token.footer!) : "null"}');
    print('  Implicit: ${implicit != null ? _bytesToHex(implicit) : "null"}');

    // 1. Генерируем ключи шифрования (Ek) и аутентификации (Ak)
    final encKeys = await _deriveKeys(keyBytes, nonce.bytes);
    final encryptionKey = encKeys.encryptionKey;
    final counterNonce = encKeys.counterNonce;
    final authKey = encKeys.authKey;

    print('  Derived encryption key: ${_bytesToHex(encryptionKey)}');
    print('  Derived counter nonce: ${_bytesToHex(counterNonce)}');
    print('  Derived auth key: ${_bytesToHex(authKey)}');

    // 2. Подготавливаем данные для проверки аутентификации
    final headerBytes = utf8.encode(header.toTokenString);
    final implicitBytes = implicit ?? <int>[];
    final footer = token.footer ?? <int>[];

    // 3. PAE(h, n, c, f, i)
    final preAuth = _pae([
      headerBytes, // h - заголовок
      nonce.bytes, // n - nonce
      secretBox.cipherText, // c - шифротекст
      footer, // f - футер (опциональный)
      implicitBytes, // i - implicit assertion (опциональный)
    ]);

    print('  PreAuth: ${_bytesToHex(preAuth)}');

    // 4. Вычисляем BLAKE2b-MAC и проверяем совпадение с MAC из токена
    final calculatedMacBytes = _computeMac(preAuth, authKey);
    final calculatedMac = Mac(calculatedMacBytes);

    print('  Calculated MAC: ${_bytesToHex(calculatedMac.bytes)}');

    // Сравниваем MAC с постоянным временем
    if (!_constantTimeEquals(calculatedMac.bytes, mac.bytes)) {
      throw SecretBoxAuthenticationError(
        message: 'Сбой аутентификации токена v4.local: MAC недействителен',
      );
    }

    // 5. Дешифруем сообщение с помощью собственной реализации XChaCha20
    // Поскольку мы уже проверили MAC, мы знаем, что сообщение целостно
    // Используем нашу собственную реализацию XChaCha20 для дешифрования
    final decryptedBytes = await _decryptCipherText(
      secretBox.cipherText,
      encryptionKey,
      counterNonce,
    );

    // 6. Возвращаем дешифрованный пакет
    return Package(
      content: decryptedBytes,
      footer: token.footer,
    );
  }

  /// Вспомогательная функция для отображения байтов в шестнадцатеричном формате
  static String _bytesToHex(List<int> bytes) {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join('');
  }

  /// Генерирует ключи для шифрования и аутентификации из основного ключа и nonce.
  static Future<_DerivedKeys> _deriveKeys(
      List<int> key, List<int> nonce) async {
    // Согласно спецификации PASETO v4, нам нужен:
    // - ключ шифрования (32 байта)
    // - counter nonce (24 байта)
    // - ключ аутентификации (32 байта)

    // Используем нашу реализацию Blake2b с поддержкой 64-байтного вывода

    // 1. Генерируем ключ шифрования и nonce
    // BLAKE2b(output=64bytes, key, 'paseto-encryption-key' || nonce)
    // Используем размер 512 бит (64 байта), из которых берем:
    // - первые 32 байта как ключ шифрования
    // - следующие 24 байта как counter nonce
    final encKeyDomain = utf8.encode(_encryptionKeyDomain);
    final encInput = Uint8List(encKeyDomain.length + nonce.length);
    encInput.setAll(0, encKeyDomain);
    encInput.setAll(encKeyDomain.length, nonce);

    // Используем нашу модифицированную библиотеку Blake2b
    // с поддержкой 64-байтного вывода для одного вызова
    final blake2bEnc = blake2lib.Blake2b(
      key: Uint8List.fromList(key),
      digestSize: 64, // 512 бит = 64 байта
    );
    final output = blake2bEnc.process(encInput);

    // Разделяем 64-байтный вывод на нужные части
    final encryptionKey =
        output.sublist(0, 32); // 32 байта для ключа шифрования
    final counterNonce = output.sublist(32, 56); // 24 байта для nonce

    // 2. Генерируем ключ аутентификации (Ak)
    // BLAKE2b(output=32bytes, key, 'paseto-auth-key-for-aead' || nonce)
    final authKeyDomain = utf8.encode(_authKeyDomain);
    final authInput = Uint8List(authKeyDomain.length + nonce.length);
    authInput.setAll(0, authKeyDomain);
    authInput.setAll(authKeyDomain.length, nonce);

    // Вычисляем ключ аутентификации с помощью Blake2b
    final blake2bAuth = blake2lib.Blake2b(
      key: Uint8List.fromList(key),
      digestSize: 32, // 256 бит = 32 байта
    );
    final authKeyData = blake2bAuth.process(authInput);

    return _DerivedKeys(
      encryptionKey: encryptionKey,
      counterNonce: counterNonce,
      authKey: authKeyData,
    );
  }

  /// Реализует Pre-Authentication Encoding (PAE) согласно спецификации PASETO.
  ///
  /// PAE упаковывает несколько частей данных в формат, который защищает от атак подмены.
  /// Формат: LE64(count) || LE64(piece1_len) || piece1 || LE64(piece2_len) || piece2 || ...
  static List<int> _pae(List<List<int>> pieces) {
    // Начинаем с 8 байт для количества элементов
    final count = pieces.length;
    final countBytes = _le64(count);

    // Вычисляем общий размер результата
    var totalSize = 8; // 8 байт для count
    for (final piece in pieces) {
      totalSize += 8; // 8 байт для длины каждого piece
      totalSize += piece.length; // длина самого piece
    }

    // Создаем буфер фиксированного размера для результата
    final result = Uint8List(totalSize);
    var offset = 0;

    // Записываем количество элементов
    for (var i = 0; i < 8; i++) {
      result[offset++] = countBytes[i];
    }

    // Для каждого элемента записываем его длину и затем сам элемент
    for (final piece in pieces) {
      final lengthBytes = _le64(piece.length);

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

  /// Преобразует целое число в массив байт в формате little-endian 64-bit.
  static Uint8List _le64(int value) {
    final result = Uint8List(8);
    final byteData = ByteData.view(result.buffer);
    byteData.setUint64(0, value, Endian.little);
    return result;
  }

  /// Сравнивает два массива байт с постоянным временем.
  static bool _constantTimeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) {
      return false;
    }

    var result = 0;
    for (var i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }

    return result == 0;
  }

  /// Вычисляет MAC с помощью нашей улучшенной реализации Blake2b
  static Uint8List _computeMac(List<int> preAuth, List<int> authKey) {
    final blake2bMac = blake2lib.Blake2b(
      key: Uint8List.fromList(authKey),
      digestSize: 32, // 256 бит
    );
    final output = blake2bMac.process(Uint8List.fromList(preAuth));
    return output;
  }

  /// Низкоуровневое дешифрование с помощью XChaCha20
  static Future<Uint8List> _decryptCipherText(
      List<int> cipherText, List<int> key, List<int> nonce) async {
    try {
      // Создаем экземпляр нашей реализации XChaCha20
      final xchacha = XChaCha20();

      // Преобразуем входные данные в правильный формат
      final keyParam = KeyParameter(Uint8List.fromList(key));

      // ВАЖНО: Для XChaCha20 нужен 24-байтный nonce
      // Первые 24 байта из counterNonce (который имеет размер 24 байта)
      final nonceBytes = Uint8List.fromList(nonce.sublist(0, 24));

      // Инициализируем с ключом и nonce для дешифрования
      xchacha.init(false, ParametersWithIV<KeyParameter>(keyParam, nonceBytes));

      // Дешифруем данные
      final decrypted = xchacha.process(Uint8List.fromList(cipherText));

      // Для отладки
      print(
          '  Decrypted bytes (first 16): ${_bytesToHex(decrypted.sublist(0, min(16, decrypted.length)))}');
      print('  Decrypted length: ${decrypted.length}');

      return decrypted;
    } catch (e) {
      print('  Ошибка в _decryptCipherText: $e');
      rethrow;
    }
  }
}
