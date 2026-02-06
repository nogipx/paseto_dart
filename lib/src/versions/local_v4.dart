// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
// SPDX-FileCopyrightText: 2026 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: MIT

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:paseto_dart/paseto_dart.dart';

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

    // 2. Шифруем сообщение с помощью нашей реализации XChaCha20
    // Создаем экземпляр нашей реализации XChaCha20
    final xchacha = XChaCha20();

    // Преобразуем входные данные в правильный формат
    final keyParam = KeyParameter(Uint8List.fromList(encryptionKey));

    // ВАЖНО: Для XChaCha20 нужен 24-байтный nonce
    // Используем все 24 байта из counterNonce
    final nonceBytes = Uint8List.fromList(counterNonce.sublist(0, 24));

    // Инициализируем с ключом и nonce для шифрования
    xchacha.init(true, ParametersWithIV<KeyParameter>(keyParam, nonceBytes));

    // Шифруем данные
    final cipherText = xchacha.process(Uint8List.fromList(package.content));

    // 3. Подготавливаем данные для аутентификации (PAE)
    final implicitBytes = implicit ?? <int>[];
    final footer = package.footer ?? <int>[];

    // 4. PAE(h, n, c, f, i)
    final headerBytes = utf8.encode(header.toTokenString);
    final preAuth = pae([
      Uint8List.fromList(headerBytes), // h - заголовок
      Uint8List.fromList(nonce), // n - nonce
      Uint8List.fromList(cipherText), // c - шифротекст
      Uint8List.fromList(footer), // f - футер (опциональный)
      Uint8List.fromList(
          implicitBytes), // i - implicit assertion (опциональный)
    ]);

    // 5. Вычисляем BLAKE2b-MAC с помощью ключа аутентификации
    final macBytes = _computeMac(preAuth, authKey);

    // 6. Создаем payload согласно спецификации PASETO v4.local
    // payload = nonce || (ciphertext + MAC)
    final cipherTextWithMac = Uint8List.fromList(cipherText + macBytes);
    final payloadBytes = Uint8List.fromList(nonce + cipherTextWithMac);

    // 7. Возвращаем PayloadLocal согласно спецификации PASETO v4.local
    return PayloadLocal(
      nonce: Mac(nonce), // Используем Mac для nonce
      secretBox: SecretBox(cipherTextWithMac,
          nonce: Uint8List.fromList(counterNonce.sublist(0, 12)),
          mac: Mac(macBytes)),
      mac: null, // MAC включен в secretBox.cipherText
      payloadBytes: payloadBytes, // Сохраняем сырые байты payload
    );
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

    // ИСПРАВЛЕНО: MAC НЕ извлекается из payload, а вычисляется отдельно
    // согласно официальной спецификации PASETO v4.local

    // 1. Генерируем ключи шифрования (Ek) и аутентификации (Ak)
    final encKeys = await _deriveKeys(keyBytes, nonce.bytes);
    final encryptionKey = encKeys.encryptionKey;
    final counterNonce = encKeys.counterNonce;
    final authKey = encKeys.authKey;

    // 2. Подготавливаем данные для проверки аутентификации
    final implicitBytes = implicit ?? <int>[];
    final footer = token.footer ?? <int>[];

    // 3. PAE(h, n, c, f, i) - c должен быть без MAC!
    final headerBytes = utf8.encode(header.toTokenString);
    final cipherTextForAuth = secretBox.cipherText.length >= 32
        ? secretBox.cipherText.sublist(0, secretBox.cipherText.length - 32)
        : secretBox.cipherText;
    final preAuth = pae([
      Uint8List.fromList(headerBytes), // h - заголовок
      Uint8List.fromList(nonce.bytes), // n - nonce
      Uint8List.fromList(cipherTextForAuth), // c - шифротекст БЕЗ MAC
      Uint8List.fromList(footer), // f - футер (опциональный)
      Uint8List.fromList(
          implicitBytes), // i - implicit assertion (опциональный)
    ]);

    // 4. Вычисляем BLAKE2b-MAC и извлекаем ожидаемый MAC из ciphertext
    final calculatedMacBytes = _computeMac(preAuth, authKey);

    // Извлекаем MAC из конца ciphertext (последние 32 байта)
    if (secretBox.cipherText.length < 32) {
      throw FormatException('Токен слишком короткий для содержания MAC');
    }

    final expectedMacBytes =
        secretBox.cipherText.sublist(secretBox.cipherText.length - 32);

    // Сравниваем MAC с постоянным временем
    if (!_constantTimeEquals(calculatedMacBytes, expectedMacBytes)) {
      throw Exception('Проверка аутентичности токена не прошла (неверный MAC)');
    }

    // 5. В официальных тестовых векторах, ciphertext содержит зашифрованные данные + MAC
    // Последние 32 байта - это MAC, который нужно отделить
    final cipherTextOnly = secretBox.cipherText.length >= 32
        ? secretBox.cipherText.sublist(0, secretBox.cipherText.length - 32)
        : secretBox.cipherText;

    // 6. Дешифруем сообщение с помощью собственной реализации XChaCha20
    // Поскольку мы уже проверили MAC, мы знаем, что сообщение целостно
    // Используем нашу собственную реализацию XChaCha20 для дешифрования
    final decrypted = await _decryptCipherText(
      cipherTextOnly,
      encryptionKey,
      counterNonce,
    );

    // 7. Возвращаем дешифрованный пакет
    return Package(
      content: decrypted,
      footer: token.footer,
    );
  }

  /// Генерирует ключи для шифрования и аутентификации из основного ключа и nonce.
  static Future<_DerivedKeys> _deriveKeys(
    List<int> key,
    List<int> nonce,
  ) async {
    // ИСПРАВЛЕНО: Точно согласно официальной спецификации PASETO v4
    // Step 4: Split the key into an Encryption key (Ek) and Authentication key (Ak)

    // 1. tmp = crypto_generichash(msg = "paseto-encryption-key" || n, key = key, length = 56)
    final encKeyDomain = utf8.encode(_encryptionKeyDomain);
    final encInput = Uint8List.fromList(encKeyDomain + nonce);

    final blake2bEnc = Blake2b(
      key: Uint8List.fromList(key),
      digestSize: 56, // ТОЧНО как в спецификации
    );
    final tmp = blake2bEnc.process(encInput);

    // 2. Ek = tmp[0:32] (первые 32 байта)
    final encryptionKey = tmp.sublist(0, 32);

    // 3. n2 = tmp[32:] (оставшиеся 24 байта) - это counter nonce для XChaCha20
    final counterNonce = tmp.sublist(32, 56); // tmp[32:] = последние 24 байта

    // 4. Ak = crypto_generichash(msg = "paseto-auth-key-for-aead" || n, key = key, length = 32)
    final authKeyDomain = utf8.encode(_authKeyDomain);
    final authInput = Uint8List.fromList(authKeyDomain + nonce);

    final blake2bAuth = Blake2b(
      key: Uint8List.fromList(key),
      digestSize: 32, // ТОЧНО как в спецификации
    );
    final authKey = blake2bAuth.process(authInput);

    return _DerivedKeys(
      encryptionKey: encryptionKey,
      counterNonce: counterNonce,
      authKey: authKey,
    );
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
    final blake2bMac = Blake2b(
      key: Uint8List.fromList(authKey),
      digestSize: 32,
    );
    final output = blake2bMac.process(Uint8List.fromList(preAuth));
    return output;
  }

  /// Низкоуровневое дешифрование с помощью XChaCha20
  static Future<Uint8List> _decryptCipherText(
    List<int> cipherText,
    List<int> key,
    List<int> nonce,
  ) async {
    // Создаем экземпляр нашей реализации XChaCha20
    final xchacha = XChaCha20();

    // Преобразуем входные данные в правильный формат
    final keyParam = KeyParameter(Uint8List.fromList(key));

    // ВАЖНО: Для XChaCha20 нужен 24-байтный nonce
    // Используем все 24 байта из nonce
    final nonceBytes = Uint8List.fromList(nonce.sublist(0, 24));

    // Инициализируем с ключом и nonce для дешифрования (false = расшифровка)
    xchacha.init(false, ParametersWithIV<KeyParameter>(keyParam, nonceBytes));

    // Дешифруем данные
    final decrypted = xchacha.process(Uint8List.fromList(cipherText));

    return decrypted;
  }

  /// Вспомогательная функция для отображения байтов в hex формате
  static String _bytesToHex(List<int> bytes) {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join('');
  }

  /// ВРЕМЕННЫЙ МЕТОД ДЛЯ ОТЛАДКИ - убрать после тестирования
  static Future<void> testDeriveKeys(List<int> key, List<int> nonce) async {
    print('=== TESTING KEY DERIVATION ===');
    print('Input Key: ${_bytesToHex(key)}');
    print('Input Nonce: ${_bytesToHex(nonce)}');

    final derived = await _deriveKeys(key, nonce);

    print('Generated Ek:  ${_bytesToHex(derived.encryptionKey)}');
    print('Generated CN:  ${_bytesToHex(derived.counterNonce)}');
    print('Generated Ak:  ${_bytesToHex(derived.authKey)}');

    print(
        'Expected  Ek:  c32b8e1c522550c8854d5177eb2ca96acc2072e3ca58407e0ee2f6470e92e49f');
    print('Expected  CN:  129a23d170eddce49867d4888d276390abf7e48e550feb7c');
    print(
        'Expected  Ak:  3d6d4c0504cbefdc54a562967ca276d0a99e0120cf154cc8624feb26da3a73e9');
  }
}
