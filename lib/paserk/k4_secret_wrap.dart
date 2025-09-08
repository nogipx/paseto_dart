import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:paseto_dart/chacha20/chacha20_pointycastle.dart';

import '../blake2/_index.dart' as blake2lib;
import '../chacha20/xchacha20.dart';
import '../utils/base64_ext.dart';
import 'k4_secret.dart';
import 'paserk_key.dart';

class K4SecretWrap extends PaserkKey {
  static const int saltLength = 32;
  static const int nonceLength = 24;
  static const int tagLength = 32;
  static const _wrappingKeyDomain = 'paserk-secret-wrap';

  K4SecretWrap(Uint8List bytes) : super(bytes, PaserkKey.k4SecretWrapPrefix);

  static Future<K4SecretWrap> wrap(K4SecretKey key, String password) async {
    if (key.rawBytes.length != K4SecretKey.keyLength) {
      throw ArgumentError('Key must be exactly ${K4SecretKey.keyLength} bytes');
    }

    // Генерируем ��лучайную соль
    final random = Random.secure();
    final salt = Uint8List(saltLength);
    for (var i = 0; i < saltLength; i++) {
      salt[i] = random.nextInt(256);
    }

    // Генерируем ключи с помощью BLAKE2b
    final wrappingKey = _deriveKey(
        utf8.encode(_wrappingKeyDomain), salt, utf8.encode(password));

    // Генерируем XChaCha20 nonce
    final nonce = Uint8List(nonceLength);
    for (var i = 0; i < nonceLength; i++) {
      nonce[i] = random.nextInt(256);
    }

    // Шифруем ключ
    final xchacha = XChaCha20();
    final keyParam = KeyParameter(wrappingKey);
    xchacha.init(true, ParametersWithIV<KeyParameter>(keyParam, nonce));
    final encrypted = xchacha.process(key.rawBytes);

    // Вычисляем тег аутентификации
    final authKey = _deriveAuthKey(salt, utf8.encode(password));
    final tag = _calculateTag(
        PaserkKey.k4SecretWrapPrefix, salt, nonce, encrypted, authKey);

    // Собираем финальный результат: tag + salt + nonce + encrypted
    final result =
        Uint8List(tagLength + saltLength + nonceLength + encrypted.length);
    var offset = 0;
    result.setAll(offset, tag);
    offset += tagLength;
    result.setAll(offset, salt);
    offset += saltLength;
    result.setAll(offset, nonce);
    offset += nonceLength;
    result.setAll(offset, encrypted);

    return K4SecretWrap(result);
  }

  static Future<K4SecretKey> unwrap(String wrappedKey, String password) async {
    if (!wrappedKey.startsWith(PaserkKey.k4SecretWrapPrefix)) {
      throw ArgumentError('Invalid k4.secret-wrap format');
    }

    final data = Uint8List.fromList(SafeBase64.decode(
        wrappedKey.substring(PaserkKey.k4SecretWrapPrefix.length)));

    if (data.length <
        tagLength + saltLength + nonceLength + K4SecretKey.keyLength) {
      throw ArgumentError('Invalid wrapped key length');
    }

    // Разбираем компоненты
    final tag = data.sublist(0, tagLength);
    final salt = data.sublist(tagLength, tagLength + saltLength);
    final nonce = data.sublist(
        tagLength + saltLength, tagLength + saltLength + nonceLength);
    final encrypted = data.sublist(tagLength + saltLength + nonceLength);

    // Проверяем тег аутентификации
    final authKey = _deriveAuthKey(salt, utf8.encode(password));
    final expectedTag = _calculateTag(
        PaserkKey.k4SecretWrapPrefix, salt, nonce, encrypted, authKey);

    if (!_compareBytes(tag, expectedTag)) {
      throw ArgumentError('Invalid authentication tag');
    }

    // Восстанавливаем ключ шифрования
    final wrappingKey = _deriveKey(
        utf8.encode(_wrappingKeyDomain), salt, utf8.encode(password));

    // Расшифровываем
    try {
      final xchacha = XChaCha20();
      final keyParam = KeyParameter(wrappingKey);
      xchacha.init(false, ParametersWithIV<KeyParameter>(keyParam, nonce));
      final decrypted = xchacha.process(encrypted);

      if (decrypted.length != K4SecretKey.keyLength) {
        throw ArgumentError('Decrypted key has invalid length');
      }

      return K4SecretKey(decrypted);
    } catch (e) {
      throw ArgumentError(
          'Failed to unwrap key: invalid password or corrupted key');
    }
  }

  static Uint8List _deriveKey(
      List<int> domain, List<int> salt, List<int> password) {
    final blake2b = blake2lib.Blake2b(
      digestSize: 32,
      key: Uint8List.fromList(password),
    );
    return blake2b.process(Uint8List.fromList(domain + salt));
  }

  static Uint8List _deriveAuthKey(List<int> salt, List<int> password) {
    return _deriveKey(utf8.encode('paserk-secret-wrap-auth'), salt, password);
  }

  static Uint8List _calculateTag(String header, List<int> salt, List<int> nonce,
      List<int> encrypted, List<int> authKey) {
    final blake2b = blake2lib.Blake2b(
      digestSize: tagLength,
      key: Uint8List.fromList(authKey),
    );
    return blake2b.process(Uint8List.fromList([
      ...utf8.encode(header),
      ...salt,
      ...nonce,
      ...encrypted,
    ]));
  }

  static bool _compareBytes(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    var result = 0;
    for (var i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result == 0;
  }

  @override
  String toString() {
    return PaserkKey.k4SecretWrapPrefix + SafeBase64.encode(rawBytes);
  }
}
