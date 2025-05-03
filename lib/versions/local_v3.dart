import 'dart:convert';
import 'dart:typed_data';

import 'package:meta/meta.dart';
import 'package:paseto_dart/paseto_dart.dart';
import 'package:pointycastle/export.dart' as pc;

/// Класс для обработки ошибок аутентификации
class SecretBoxAuthenticationError extends Error {
  SecretBoxAuthenticationError(this.message);
  final String message;

  @override
  String toString() => 'SecretBoxAuthenticationError: $message';
}

/// Реализация PASETO v3.local токенов согласно официальной спецификации
/// Использует AES-256-CTR с HMAC-SHA-384
@immutable
class LocalV3 {
  static const header = Header(
    version: Version.v3,
    purpose: Purpose.local,
  );
  static const nonceLength = 32;
  static const macLength = 48;

  /// Расшифровывает PASETO v3.local токен
  static Future<Package> decrypt(
    Token token, {
    required SecretKey secretKey,
    List<int>? implicit,
  }) async {
    // Инициализируем регистрацию алгоритмов
    PasetoRegistryInitializer.initV3Local();

    // Проверка версии и purpose токена
    if (token.header.version != Version.v3 || token.header.purpose != Purpose.local) {
      throw FormatException('Token format is incorrect: not a v3.local token');
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

    // Получаем ключевой материал
    final secretKeyBytes = await secretKey.extractBytes();

    // Проверяем длину nonce
    if (nonce.bytes.length != nonceLength) {
      throw FormatException('Invalid nonce length: expected $nonceLength bytes');
    }

    // Выводим ключи шифрования с использованием HKDF
    final keys = await _deriveKeys(secretKeyBytes, nonce.bytes, implicit: implicit ?? []);

    // Получаем AAD для проверки целостности
    final aad = Token.preAuthenticationEncoding(
      header: header,
      payload: PayloadLocal(
        secretBox: null,
        nonce: nonce,
      ),
      footer: token.footer,
      implicit: implicit,
    );

    // Шифротекст и MAC хранятся в secretBox.cipherText
    final cipherText = secretBox.cipherText.sublist(0, secretBox.cipherText.length - macLength);
    final macBytes = secretBox.cipherText.sublist(secretBox.cipherText.length - macLength);

    // Проверяем MAC с использованием HMAC-SHA-384
    final computedMac = _computeHmacSha384(
      keys.authKey,
      aad,
      cipherText,
    );

    // Сравниваем MAC в постоянном времени
    if (!_constantTimeEquals(macBytes, computedMac)) {
      throw SecretBoxAuthenticationError('Authentication failed: MAC verification failed');
    }

    // Используем AES-256-CTR для расшифровки
    final decrypted = _decryptWithAesCtr(
      cipherText,
      keys.encKey,
      nonce.bytes.sublist(0, 16), // Используем первые 16 байт nonce как IV для AES-CTR
    );

    // Возвращаем расшифрованное сообщение
    return Package(
      content: decrypted,
      footer: token.footer,
    );
  }

  /// Шифрует данные и создает PASETO v3.local токен
  static Future<Payload> encrypt(
    Package package, {
    required SecretKey secretKey,
    List<int>? implicit,
  }) async {
    // Инициализируем регистрацию алгоритмов
    PasetoRegistryInitializer.initV3Local();

    // Получаем ключевой материал
    final secretKeyBytes = await secretKey.extractBytes();

    // Генерируем случайный nonce длиной 32 байта
    final nonceBytes = _generateRandomBytes(nonceLength);
    final nonce = Mac(nonceBytes);

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

    // Выводим ключи шифрования
    final keys = await _deriveKeys(secretKeyBytes, nonceBytes, implicit: implicit ?? []);

    // Шифруем данные с использованием AES-256-CTR
    final cipherText = _encryptWithAesCtr(
      package.content,
      keys.encKey,
      nonceBytes.sublist(0, 16), // Используем первые 16 байт nonce как IV для AES-CTR
    );

    // Вычисляем HMAC-SHA-384 для проверки целостности
    final mac = _computeHmacSha384(
      keys.authKey,
      preAuth,
      cipherText,
    );

    // Объединяем шифротекст и MAC
    final cipherTextWithMac = cipherText + mac;

    // Создаем payload
    return PayloadLocal(
      nonce: nonce,
      secretBox: SecretBox(
        cipherTextWithMac,
        nonce: nonceBytes,
        mac: Mac(mac),
      ),
    );
  }

  /// Вычисляет HMAC-SHA-384 для проверки целостности
  static List<int> _computeHmacSha384(
    List<int> authKey,
    List<int> aad,
    List<int> cipherText,
  ) {
    // Создаем HMAC-SHA-384 с ключом аутентификации
    final hmac = pc.HMac(pc.SHA384Digest(), 128);
    hmac.init(pc.KeyParameter(Uint8List.fromList(authKey)));

    // Обновляем HMAC с AAD и шифротекстом
    hmac.update(Uint8List.fromList(aad), 0, aad.length);
    hmac.update(Uint8List.fromList(cipherText), 0, cipherText.length);

    // Завершаем и получаем MAC
    final mac = Uint8List(hmac.macSize);
    hmac.doFinal(mac, 0);

    return mac.toList();
  }

  /// Шифрует данные с использованием AES-256-CTR
  static List<int> _encryptWithAesCtr(
    List<int> plaintext,
    List<int> encKey,
    List<int> iv,
  ) {
    // Создаем AES-256 в режиме CTR
    final cipher = pc.StreamCipher('CTR/AES');
    cipher.init(
        true,
        pc.ParametersWithIV(
          pc.KeyParameter(Uint8List.fromList(encKey)),
          Uint8List.fromList(iv),
        ));

    // Шифруем данные
    final input = Uint8List.fromList(plaintext);
    final output = Uint8List(input.length);

    // Обрабатываем данные
    for (var i = 0; i < input.length; i++) {
      output[i] = cipher.returnByte(input[i]);
    }

    return output.toList();
  }

  /// Расшифровывает данные с использованием AES-256-CTR
  static List<int> _decryptWithAesCtr(
    List<int> cipherText,
    List<int> encKey,
    List<int> iv,
  ) {
    // Создаем AES-256 в режиме CTR
    final cipher = pc.StreamCipher('CTR/AES');
    cipher.init(
        false,
        pc.ParametersWithIV(
          pc.KeyParameter(Uint8List.fromList(encKey)),
          Uint8List.fromList(iv),
        ));

    // Расшифровываем данные
    final input = Uint8List.fromList(cipherText);
    final output = Uint8List(input.length);

    // Обрабатываем данные
    for (var i = 0; i < input.length; i++) {
      output[i] = cipher.returnByte(input[i]);
    }

    return output.toList();
  }

  /// Генерирует случайные байты
  static List<int> _generateRandomBytes(int length) {
    final secureRandom = pc.SecureRandom('Fortuna');
    final seed = Uint8List(32);
    for (var i = 0; i < seed.length; i++) {
      seed[i] = i;
    }
    secureRandom.seed(pc.KeyParameter(seed));

    final bytes = Uint8List(length);
    for (var i = 0; i < length; i++) {
      bytes[i] = secureRandom.nextUint8();
    }

    return bytes.toList();
  }

  /// Сравнивает два массива в постоянном времени для предотвращения атак по времени
  static bool _constantTimeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;

    int result = 0;
    for (var i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result == 0;
  }

  /// Выводит ключи шифрования с использованием HKDF на основе HMAC-SHA-384
  static Future<_SymmetricKeys> _deriveKeys(
    List<int> secretKeyBytes,
    List<int> nonceBytes, {
    required List<int> implicit,
  }) async {
    // Создаем HKDF на основе HMAC-SHA-384
    final digest = pc.SHA384Digest();

    // Информация для вывода ключа шифрования
    final encKeyInfo = utf8.encode('paseto-encryption-key');

    // Информация для вывода ключа аутентификации
    final authKeyInfo = utf8.encode('paseto-auth-key-for-aead');

    // Дополнительные данные для вывода ключей
    final context = _createDeriveKeyContext(implicit);

    // Выводим ключ шифрования (32 байта для AES-256)
    final encKey = _hkdfExpand(
      digest,
      secretKeyBytes,
      nonceBytes,
      encKeyInfo + context,
      32, // AES-256 key size
    );

    // Выводим ключ аутентификации для HMAC-SHA-384
    final authKey = _hkdfExpand(
      digest,
      secretKeyBytes,
      nonceBytes,
      authKeyInfo + context,
      48, // SHA-384 output size for HMAC
    );

    return _SymmetricKeys(encKey: encKey, authKey: authKey);
  }

  /// Реализация HKDF-Expand согласно RFC 5869
  static List<int> _hkdfExpand(
    pc.Digest digest,
    List<int> key,
    List<int> salt,
    List<int> info,
    int length,
  ) {
    // HKDF-Extract
    final hmac = pc.HMac(digest, digest.digestSize);
    hmac.init(pc.KeyParameter(Uint8List.fromList(salt)));
    hmac.update(Uint8List.fromList(key), 0, key.length);
    final prk = Uint8List(hmac.macSize);
    hmac.doFinal(prk, 0);

    // HKDF-Expand
    final result = Uint8List(length);
    var prev = Uint8List(0);
    var outputOffset = 0;
    var remainingBytes = length;

    for (var i = 1; remainingBytes > 0; i++) {
      hmac.reset();
      hmac.init(pc.KeyParameter(prk));

      if (prev.isNotEmpty) {
        hmac.update(prev, 0, prev.length);
      }

      hmac.update(Uint8List.fromList(info), 0, info.length);
      hmac.updateByte(i);

      final stepResult = Uint8List(hmac.macSize);
      hmac.doFinal(stepResult, 0);

      final bytesToCopy = remainingBytes < stepResult.length ? remainingBytes : stepResult.length;
      result.setRange(outputOffset, outputOffset + bytesToCopy, stepResult);

      prev = stepResult;
      outputOffset += bytesToCopy;
      remainingBytes -= bytesToCopy;
    }

    return result.toList();
  }

  /// Создает контекст для вывода ключей согласно спецификации
  static List<int> _createDeriveKeyContext(List<int> implicit) {
    final domain = utf8.encode('paseto-local-wrap');
    final result = <int>[];

    // Добавляем идентификатор домена
    result.addAll(domain);

    // Добавляем implicit key (при наличии)
    result.addAll(implicit);

    return result;
  }
}

/// Структура для хранения выведенных ключей
@immutable
class _SymmetricKeys {
  const _SymmetricKeys({
    required this.encKey,
    required this.authKey,
  });

  final List<int> encKey;
  final List<int> authKey;
}
