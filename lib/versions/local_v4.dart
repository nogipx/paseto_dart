// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'dart:convert';
import 'dart:typed_data';
import 'dart:math' as math;

import 'package:meta/meta.dart';
import 'package:paseto_dart/paseto_dart.dart';
import 'package:pointycastle/export.dart' as pc;

/// Реализация PASETO v4.local токенов согласно официальной спецификации
/// Использует XChaCha20-Poly1305 для аутентифицированного шифрования
/// с использованием BLAKE2b для HKDF
@immutable
class LocalV4 {
  static const header = Header(
    version: Version.v4,
    purpose: Purpose.local,
  );
  static const nonceLength = 32;
  static const macLength =
      32; // В v4 используется 32-байтовый MAC (BLAKE2b-256)
  static const encKeyLength = 32; // XChaCha20 ключ
  static const authKeyLength = 32; // BLAKE2b-MAC ключ

  // Константы для HKDF
  static const encKeyInfo = "paseto-encryption-key";
  static const authKeyInfo = "paseto-auth-key-for-aead";

  /// Расшифровывает PASETO v4.local токен и проверяет его целостность
  static Future<Package> decrypt(
    Token token, {
    required SecretKey secretKey,
    List<int>? implicit,
  }) async {
    // Инициализируем регистр PointyCastle для v4.local
    PasetoRegistryInitializer.initV4Local();

    // Проверка версии и purpose токена
    if (token.header.version != Version.v4 ||
        token.header.purpose != Purpose.local) {
      throw FormatException('Token format is incorrect: not a v4.local token');
    }

    final payload = token.payloadLocal;
    if (payload == null) throw UnsupportedError('Invalid payload type.');
    final secretBox = payload.secretBox;
    final nonce = payload.nonce;
    if (nonce == null) {
      throw Exception('Missing nonce');
    }
    if (secretBox == null) {
      throw Exception('Missing secretBox');
    }

    // Проверяем длину nonce
    if (nonce.bytes.length != nonceLength) {
      throw FormatException(
          'Invalid nonce length: expected $nonceLength bytes, got ${nonce.bytes.length}');
    }

    // Получаем ключевой материал
    final secretKeyBytes = await secretKey.extractBytes();
    if (secretKeyBytes.length < 32) {
      throw FormatException('Secret key must be at least 32 bytes');
    }

    // Выводим ключи шифрования и аутентификации с использованием BLAKE2b-HKDF
    final keys = _deriveKeys(
      secretKeyBytes,
      nonce.bytes,
      implicit: implicit ?? [],
    );

    // Создаем pre-authentication encoding (PAE) для проверки целостности
    final preAuth = Token.preAuthenticationEncoding(
      header: header,
      payload: PayloadLocal(
        secretBox: null,
        nonce: nonce,
      ),
      footer: token.footer,
      implicit: implicit,
    );

    // Проверяем минимальную длину сообщения (должен быть как минимум один байт данных + MAC)
    if (secretBox.cipherText.length <= macLength) {
      throw FormatException(
          'Ciphertext too short: expected more than $macLength bytes');
    }

    // Получаем шифротекст и MAC
    final cipherText = secretBox.cipherText
        .sublist(0, secretBox.cipherText.length - macLength);
    final providedMac =
        secretBox.cipherText.sublist(secretBox.cipherText.length - macLength);

    // Вычисляем MAC с использованием BLAKE2b
    final computedMac = _computeBlake2bMac(
      keys.authKey,
      preAuth,
      cipherText,
    );

    // Сравниваем MAC в постоянном времени для предотвращения атак по времени
    if (!_constantTimeEquals(providedMac, computedMac)) {
      throw SecretBoxAuthenticationError(
          'Authentication failed: MAC verification failed');
    }

    // Расшифровываем данные с использованием XChaCha20
    final decrypted = await _decryptXChaCha20(
      cipherText,
      keys.encKey,
      nonce.bytes.sublist(0, 24), // XChaCha20 использует 24-байтовый nonce
    );

    // Возвращаем расшифрованное сообщение
    return Package(
      content: decrypted,
      footer: token.footer,
    );
  }

  /// Шифрует данные и создает PASETO v4.local токен
  static Future<Payload> encrypt(
    Package package, {
    required SecretKey secretKey,
    List<int>? implicit,
  }) async {
    // Инициализируем регистр PointyCastle для v4.local
    PasetoRegistryInitializer.initV4Local();

    // Получаем ключевой материал
    final secretKeyBytes = await secretKey.extractBytes();
    if (secretKeyBytes.length < 32) {
      throw FormatException('Secret key must be at least 32 bytes');
    }

    // Генерируем случайный nonce длиной 32 байта для v4
    final random = math.Random.secure();
    final nonceBytes = Uint8List(nonceLength);
    for (var i = 0; i < nonceLength; i++) {
      nonceBytes[i] = random.nextInt(256);
    }
    final nonce = MacWrapper(nonceBytes);

    // Создаем pre-authentication encoding (PAE)
    final preAuth = Token.preAuthenticationEncoding(
      header: header,
      payload: PayloadLocal(
        secretBox: null,
        nonce: nonce,
      ),
      footer: package.footer,
      implicit: implicit,
    );

    // Получаем ключи шифрования и аутентификации через BLAKE2b HKDF
    final keys = _deriveKeys(
      secretKeyBytes,
      nonceBytes,
      implicit: implicit ?? [],
    );

    // Шифруем данные с использованием XChaCha20
    final cipherText = await _encryptXChaCha20(
      package.content,
      keys.encKey,
      nonceBytes.sublist(0, 24), // XChaCha20 использует 24-байтовый nonce
    );

    // Вычисляем MAC с использованием BLAKE2b
    final mac = _computeBlake2bMac(
      keys.authKey,
      preAuth,
      cipherText,
    );

    // Объединяем шифротекст и MAC в одно поле
    final cipherTextWithMac = Uint8List(cipherText.length + mac.length);
    cipherTextWithMac.setAll(0, cipherText);
    cipherTextWithMac.setAll(cipherText.length, mac);

    // Создаем payload
    return PayloadLocal(
      nonce: nonce,
      secretBox: SecretBox(
        cipherTextWithMac,
        nonce: nonceBytes,
        mac: MacWrapper(mac),
      ),
    );
  }

  /// Выводит ключи шифрования и аутентификации с использованием BLAKE2b-HKDF
  static _KeySet _deriveKeys(
    List<int> key,
    List<int> nonce, {
    List<int> implicit = const [],
  }) {
    // Создаем информацию для HKDF
    final encInfo = utf8.encode(encKeyInfo) + nonce;
    final authInfo = utf8.encode(authKeyInfo) + nonce;

    // Blake2b для получения ключа шифрования
    final encBlake = pc.Blake2bDigest(digestSize: encKeyLength);
    encBlake.update(Uint8List.fromList(key), 0, key.length);
    encBlake.update(Uint8List.fromList(encInfo), 0, encInfo.length);
    final encKey = Uint8List(encKeyLength);
    encBlake.doFinal(encKey, 0);

    // Blake2b для получения ключа аутентификации
    final authBlake = pc.Blake2bDigest(digestSize: authKeyLength);
    authBlake.update(Uint8List.fromList(key), 0, key.length);
    authBlake.update(Uint8List.fromList(authInfo), 0, authInfo.length);
    final authKey = Uint8List(authKeyLength);
    authBlake.doFinal(authKey, 0);

    return _KeySet(
      encKey: encKey.toList(),
      authKey: authKey.toList(),
    );
  }

  /// Вычисляет MAC на основе BLAKE2b для v4.local
  static List<int> _computeBlake2bMac(
    List<int> authKey,
    List<int> aad,
    List<int> cipherText,
  ) {
    // Создаем BLAKE2b-256 MAC
    final mac = pc.Mac('BLAKE2b/256')
      ..init(pc.KeyParameter(Uint8List.fromList(authKey)));

    // Добавляем данные для аутентификации
    mac.update(Uint8List.fromList(aad), 0, aad.length);
    mac.update(Uint8List.fromList(cipherText), 0, cipherText.length);

    // Вычисляем MAC
    final result = Uint8List(macLength);
    mac.doFinal(result, 0);
    return result.toList();
  }

  /// Шифрует данные с использованием XChaCha20
  static Future<List<int>> _encryptXChaCha20(
    List<int> plaintext,
    List<int> key,
    List<int> nonce,
  ) async {
    // Инициализируем регистр PointyCastle для v2.local (ChaCha20-Poly1305)
    PasetoRegistryInitializer.initV2Local();

    // XChaCha20 = HChaCha20(key, nonce[:16]) + ChaCha20(derived_key, nonce[16:], 0)

    // 1. Вычисляем HChaCha20 ключ из основного ключа и первых 16 байт nonce
    final hChaChaKey = _deriveHChaChaKey(key, nonce.sublist(0, 16));

    // 2. Используем ChaCha7539 для шифрования
    final cipher = pc.StreamCipher('ChaCha7539');
    final keyParam = pc.KeyParameter(Uint8List.fromList(hChaChaKey));

    // Создаем nonce для ChaCha20 (12 байт): 4 байта 0 + последние 8 байт nonce
    final iv = Uint8List(12);
    iv.setAll(4, nonce.sublist(16, 24)); // Используем последние 8 байт nonce

    final params = pc.ParametersWithIV(keyParam, iv);
    cipher.init(true, params);

    // Шифруем данные
    final output = Uint8List(plaintext.length);
    for (var i = 0; i < plaintext.length; i++) {
      output[i] = cipher.returnByte(plaintext[i]);
    }

    return output.toList();
  }

  /// Расшифровывает данные с использованием XChaCha20
  static Future<List<int>> _decryptXChaCha20(
    List<int> cipherText,
    List<int> key,
    List<int> nonce,
  ) async {
    // Инициализируем регистр PointyCastle для v2.local (ChaCha20-Poly1305)
    PasetoRegistryInitializer.initV2Local();

    // 1. Вычисляем HChaCha20 ключ из основного ключа и первых 16 байт nonce
    final hChaChaKey = _deriveHChaChaKey(key, nonce.sublist(0, 16));

    // 2. Используем ChaCha7539 для расшифровки
    final cipher = pc.StreamCipher('ChaCha7539');
    final keyParam = pc.KeyParameter(Uint8List.fromList(hChaChaKey));

    // Создаем nonce для ChaCha20 (12 байт): 4 байта 0 + последние 8 байт nonce
    final iv = Uint8List(12);
    iv.setAll(4, nonce.sublist(16, 24)); // Используем последние 8 байт nonce

    final params = pc.ParametersWithIV(keyParam, iv);
    cipher.init(false, params);

    // Расшифровываем данные
    final output = Uint8List(cipherText.length);
    for (var i = 0; i < cipherText.length; i++) {
      output[i] = cipher.returnByte(cipherText[i]);
    }

    return output.toList();
  }

  /// Создает HChaCha20 промежуточный ключ из основного ключа и первых 16 байт nonce
  static List<int> _deriveHChaChaKey(List<int> key, List<int> nonce) {
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
  static int _bytesToWord(List<int> bytes, int offset) {
    return (bytes[offset] & 0xFF) |
        ((bytes[offset + 1] & 0xFF) << 8) |
        ((bytes[offset + 2] & 0xFF) << 16) |
        ((bytes[offset + 3] & 0xFF) << 24);
  }

  // Преобразует 32-битное слово в 4 байта (little-endian)
  static void _wordToBytes(int word, Uint8List bytes, int offset) {
    bytes[offset] = word & 0xFF;
    bytes[offset + 1] = (word >> 8) & 0xFF;
    bytes[offset + 2] = (word >> 16) & 0xFF;
    bytes[offset + 3] = (word >> 24) & 0xFF;
  }

  // Выполняет раунды ChaCha20
  static void _chachaRounds(List<int> state) {
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
  static void _quarterRound(List<int> x, int a, int b, int c, int d) {
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
  static int _add32(int a, int b) {
    return (a + b) & 0xFFFFFFFF;
  }

  // Циклический сдвиг влево
  static int _rotl32(int x, int n) {
    return ((x << n) & 0xFFFFFFFF) | ((x & 0xFFFFFFFF) >> (32 - n));
  }

  /// Сравнивает два списка байт в постоянном времени
  static bool _constantTimeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;

    int result = 0;
    for (var i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result == 0;
  }
}

/// Класс, содержащий ключи шифрования и аутентификации
class _KeySet {
  final List<int> encKey;
  final List<int> authKey;

  _KeySet({
    required this.encKey,
    required this.authKey,
  });
}

/// Обертка для Mac чтобы избежать конфликтов имен с PointyCastle
@immutable
class MacWrapper implements Mac {
  const MacWrapper(this._bytes);

  final List<int> _bytes;

  @override
  List<int> get bytes => _bytes;

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! Mac) return false;

    if (bytes.length != other.bytes.length) return false;

    for (var i = 0; i < bytes.length; i++) {
      if (bytes[i] != other.bytes[i]) return false;
    }

    return true;
  }

  @override
  int get hashCode => Object.hashAll(bytes);
}

/// Исключение возникающее при неправильном MAC
class SecretBoxAuthenticationError extends Error {
  SecretBoxAuthenticationError(this.message);
  final String message;

  @override
  String toString() => 'SecretBoxAuthenticationError: $message';
}
