// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'dart:math' as dart_math;
import 'dart:typed_data';

import 'package:meta/meta.dart';
import 'package:paseto_dart/models/crypto.dart';
import 'package:paseto_dart/models/exceptions.dart';
import 'package:pointycastle/export.dart' as pc;

/// Реализация XChaCha20-Poly1305 для AEAD шифрования согласно спецификации PASETO
@immutable
class XChaCha20Poly1305 {
  const XChaCha20Poly1305();

  /// Размер MAC (в байтах)
  static const macSize = 16;

  /// Размер nonce (в байтах)
  static const nonceSize = 24;

  /// Генерирует криптографически стойкий SecretKey
  Future<SecretKey> newSecretKey() async {
    final secureRandom = _getSecureRandom();
    final keyBytes = Uint8List(32);
    for (var i = 0; i < keyBytes.length; i++) {
      keyBytes[i] = secureRandom.nextUint8();
    }
    return SecretKeyData(keyBytes.toList());
  }

  /// Генерирует случайный nonce
  Future<List<int>> newNonce() async {
    final secureRandom = _getSecureRandom();
    final nonceBytes = Uint8List(nonceSize);
    for (var i = 0; i < nonceBytes.length; i++) {
      nonceBytes[i] = secureRandom.nextUint8();
    }
    return nonceBytes.toList();
  }

  /// Шифрует данные с дополнительной аутентификацией (AAD)
  /// Согласно спецификации PASETO v2.local
  Future<SecretBox> encrypt(
    List<int> plaintext, {
    required List<int> nonce,
    required List<int> aad,
    required SecretKey secretKey,
  }) async {
    final keyBytes = await secretKey.extractBytes();

    // Проверяем размеры ключа и nonce
    if (keyBytes.length != 32) {
      throw ArgumentError(
          'Secret key must be 32 bytes (256 bits) for XChaCha20-Poly1305');
    }

    if (nonce.length != nonceSize) {
      throw ArgumentError(
          'Nonce must be $nonceSize bytes for XChaCha20-Poly1305');
    }

    // Выводим подключи для ChaCha20 и Poly1305
    final subkeys = _deriveSubkeys(keyBytes, nonce);

    // Шифруем данные с помощью ChaCha20
    final cipher = pc.StreamCipher('ChaCha7539');
    final keyParam = pc.KeyParameter(Uint8List.fromList(subkeys.encKey));

    // Используем только 12 байт для IV ChaCha20
    final iv = Uint8List(12);
    iv.setAll(4, nonce.sublist(16, 24)); // Используем последние 8 байт nonce

    final params = pc.ParametersWithIV(keyParam, iv);
    cipher.init(true, params);

    // Шифруем данные
    final cipherText = Uint8List(plaintext.length);
    for (var i = 0; i < plaintext.length; i++) {
      cipherText[i] = cipher.returnByte(plaintext[i]);
    }

    // Создаем Poly1305 MAC
    final mac = _computePoly1305Mac(
      macKey: subkeys.macKey,
      aad: aad,
      cipherText: cipherText.toList(),
    );

    return SecretBox(
      cipherText.toList(),
      nonce: nonce,
      mac: Mac(mac),
    );
  }

  /// Расшифровывает данные и проверяет аутентификацию
  /// Согласно спецификации PASETO v2.local
  Future<List<int>> decrypt(
    SecretBox secretBox, {
    required List<int> aad,
    required SecretKey secretKey,
  }) async {
    final keyBytes = await secretKey.extractBytes();
    final nonce = secretBox.nonce;
    final cipherText = secretBox.cipherText;
    final macBytes = secretBox.mac.bytes;

    // Проверяем размеры ключа и nonce
    if (keyBytes.length != 32) {
      throw ArgumentError(
          'Secret key must be 32 bytes (256 bits) for XChaCha20-Poly1305');
    }

    if (nonce.length != nonceSize) {
      throw ArgumentError(
          'Nonce must be $nonceSize bytes for XChaCha20-Poly1305');
    }

    // Выводим подключи для ChaCha20 и Poly1305
    final subkeys = _deriveSubkeys(keyBytes, nonce);

    // Проверяем MAC перед расшифровкой
    final expectedMac = _computePoly1305Mac(
      macKey: subkeys.macKey,
      aad: aad,
      cipherText: cipherText,
    );

    // Проверка MAC
    if (!_constantTimeEquals(macBytes, expectedMac)) {
      throw SecretBoxAuthenticationError(
          'Authentication failed: MAC verification failed');
    }

    // Расшифровываем данные
    final cipher = pc.StreamCipher('ChaCha7539');
    final keyParam = pc.KeyParameter(Uint8List.fromList(subkeys.encKey));

    // Используем только 12 байт для IV ChaCha20
    final iv = Uint8List(12);
    iv.setAll(4, nonce.sublist(16, 24)); // Используем последние 8 байт nonce

    final params = pc.ParametersWithIV(keyParam, iv);
    cipher.init(false, params);

    // Расшифровываем данные
    final plaintext = Uint8List(cipherText.length);
    for (var i = 0; i < cipherText.length; i++) {
      plaintext[i] = cipher.returnByte(cipherText[i]);
    }

    return plaintext.toList();
  }

  /// Выводит подключи для ChaCha20 и Poly1305
  _XChaCha20Poly1305Subkeys _deriveSubkeys(
      List<int> keyBytes, List<int> nonce) {
    // Для XChaCha20-Poly1305 используем Poly1305 Key Derivation согласно спецификации
    // 1. Создаем HChaCha20 для получения подключа
    final hChaChaKey = _deriveHChaChaKey(keyBytes, nonce.sublist(0, 16));

    // 2. Создаем ChaCha20 для получения одноразового ключа Poly1305
    final chacha = pc.StreamCipher('ChaCha7539');
    final subNonce = Uint8List(12); // Используем 12-байтовый nonce для ChaCha20
    subNonce.setAll(
        4, nonce.sublist(16, 24)); // Добавляем оставшиеся байты nonce

    final keyParam = pc.KeyParameter(Uint8List.fromList(hChaChaKey));
    final params = pc.ParametersWithIV(keyParam, subNonce);
    chacha.init(true, params);

    // Генерируем одноразовый ключ для Poly1305
    final poly1305Key = Uint8List(32);
    final zeroBlock = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      poly1305Key[i] = chacha.returnByte(zeroBlock[i]);
    }

    return _XChaCha20Poly1305Subkeys(
      encKey: hChaChaKey,
      macKey: poly1305Key.toList(),
    );
  }

  /// Создает HChaCha20 промежуточный ключ из основного ключа и первых 16 байт nonce
  List<int> _deriveHChaChaKey(List<int> key, List<int> nonce) {
    // Реализация HChaCha20 согласно спецификации XChaCha20:
    // https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-00

    // ChaCha20 состояние инициализируется следующим образом:
    // Константы: 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 (первые 4 слова)
    // Ключ: 8 слов (32 байта)
    // Входные данные: 4 слова (16 байт) nonce

    // ChaCha20 константы (литералы "expand 32-byte k" в little-endian)
    final state = List<int>.filled(16, 0);
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Заполняем состояние ключом (8 слов)
    for (int i = 0; i < 8; i++) {
      state[i + 4] = _bytesToWord(key, i * 4);
    }

    // Заполняем состояние nonce (4 слова)
    for (int i = 0; i < 4; i++) {
      state[i + 12] = _bytesToWord(nonce, i * 4);
    }

    // Выполняем 20 раундов ChaCha20
    _chachaRounds(state);

    // В отличие от ChaCha20, HChaCha20 возвращает
    // первые 4 слова и последние 4 слова состояния
    final result = Uint8List(32);
    for (int i = 0; i < 4; i++) {
      _wordToBytes(state[i], result, i * 4);
      _wordToBytes(state[i + 12], result, (i + 4) * 4);
    }

    return result.toList();
  }

  // Преобразует 4 байта в 32-битное слово (little-endian)
  int _bytesToWord(List<int> bytes, int offset) {
    return (bytes[offset] & 0xFF) |
        ((bytes[offset + 1] & 0xFF) << 8) |
        ((bytes[offset + 2] & 0xFF) << 16) |
        ((bytes[offset + 3] & 0xFF) << 24);
  }

  // Преобразует 32-битное слово в 4 байта (little-endian)
  void _wordToBytes(int word, Uint8List bytes, int offset) {
    bytes[offset] = word & 0xFF;
    bytes[offset + 1] = (word >> 8) & 0xFF;
    bytes[offset + 2] = (word >> 16) & 0xFF;
    bytes[offset + 3] = (word >> 24) & 0xFF;
  }

  // Выполняет раунды ChaCha20
  void _chachaRounds(List<int> state) {
    // Сохраняем исходное состояние
    final x = List<int>.from(state);

    // 20 раундов (10 двойных раундов)
    for (int i = 0; i < 10; i++) {
      // Вертикальные четверки
      _quarterRound(x, 0, 4, 8, 12);
      _quarterRound(x, 1, 5, 9, 13);
      _quarterRound(x, 2, 6, 10, 14);
      _quarterRound(x, 3, 7, 11, 15);

      // Диагональные четверки
      _quarterRound(x, 0, 5, 10, 15);
      _quarterRound(x, 1, 6, 11, 12);
      _quarterRound(x, 2, 7, 8, 13);
      _quarterRound(x, 3, 4, 9, 14);
    }

    // Копируем результат обратно в состояние
    for (int i = 0; i < 16; i++) {
      state[i] = x[i];
    }
  }

  // Квартер-раунд ChaCha20
  void _quarterRound(List<int> x, int a, int b, int c, int d) {
    x[a] = _add32(x[a], x[b]);
    x[d] = _rotl32(x[d] ^ x[a], 16);

    x[c] = _add32(x[c], x[d]);
    x[b] = _rotl32(x[b] ^ x[c], 12);

    x[a] = _add32(x[a], x[b]);
    x[d] = _rotl32(x[d] ^ x[a], 8);

    x[c] = _add32(x[c], x[d]);
    x[b] = _rotl32(x[b] ^ x[c], 7);
  }

  // Сложение по модулю 2^32
  int _add32(int a, int b) {
    return (a + b) & 0xFFFFFFFF;
  }

  // Циклический сдвиг влево
  int _rotl32(int x, int n) {
    return ((x << n) & 0xFFFFFFFF) | ((x & 0xFFFFFFFF) >> (32 - n));
  }

  /// Вычисляет Poly1305 MAC согласно спецификации PASETO
  List<int> _computePoly1305Mac({
    required List<int> macKey,
    required List<int> aad,
    required List<int> cipherText,
  }) {
    // Создаем Poly1305 с полученным ключом
    final poly1305 = pc.Mac('POLY1305');
    poly1305.init(pc.KeyParameter(Uint8List.fromList(macKey)));

    // Обновляем MAC с AAD и шифротекстом согласно спецификации
    poly1305.update(Uint8List.fromList(aad), 0, aad.length);
    poly1305.update(Uint8List.fromList(cipherText), 0, cipherText.length);

    // Добавляем длины AAD и шифротекста в формате little-endian (8 байт каждая)
    final lengthBlock = Uint8List(16);
    _writeLittleEndian(lengthBlock, 0, aad.length);
    _writeLittleEndian(lengthBlock, 8, cipherText.length);
    poly1305.update(lengthBlock, 0, lengthBlock.length);

    // Завершаем и получаем MAC
    final mac = Uint8List(16);
    poly1305.doFinal(mac, 0);

    return mac.toList();
  }

  /// Записывает 64-битное целое число в формате little-endian
  void _writeLittleEndian(Uint8List output, int offset, int value) {
    output[offset] = value & 0xFF;
    output[offset + 1] = (value >> 8) & 0xFF;
    output[offset + 2] = (value >> 16) & 0xFF;
    output[offset + 3] = (value >> 24) & 0xFF;
    output[offset + 4] = 0;
    output[offset + 5] = 0;
    output[offset + 6] = 0;
    output[offset + 7] = 0;
  }

  /// Сравнивает два массива в постоянном времени для предотвращения атак по времени
  bool _constantTimeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;

    int result = 0;
    for (var i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result == 0;
  }

  /// Получает криптографически стойкий генератор случайных чисел
  pc.SecureRandom _getSecureRandom() {
    // Получаем FortunaRandom из реестра PointyCastle
    final secureRandom = pc.SecureRandom('Fortuna');

    // Автоматически затравливаем из источника энтропии
    final seed = Uint8List(32);
    final seedSource = dart_math.Random.secure();
    for (var i = 0; i < seed.length; i++) {
      seed[i] = seedSource.nextInt(256);
    }

    secureRandom.seed(pc.KeyParameter(seed));
    return secureRandom;
  }
}

/// Контейнер для подключей XChaCha20-Poly1305
@immutable
class _XChaCha20Poly1305Subkeys {
  const _XChaCha20Poly1305Subkeys({
    required this.encKey,
    required this.macKey,
  });

  final List<int> encKey;
  final List<int> macKey;
}
