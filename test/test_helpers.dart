import 'dart:convert';
import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:paseto_dart/paseto_dart.dart' as paseto;

/// Тип ключевой пары, используемый в тестах
enum TestKeyPairType {
  ed25519,
  ecdsa384,
  ecdsa521,
}

/// Упрощенная реализация PublicKey для тестов
class SimplePublicKey extends paseto.PublicKey {
  SimplePublicKey(this._bytes, {required this.type});

  final List<int> _bytes;
  final TestKeyPairType type;

  @override
  Future<List<int>> get bytes async => _bytes;
}

/// Расширение для KeyPair
extension KeyPairExtension on paseto.KeyPair {
  /// Возвращает только публичный ключ из пары
  Future<paseto.PublicKey> extractPublicKey() async {
    return publicKey;
  }
}

/// Вспомогательные функции для тестов
class TestHelpers {
  /// Генерирует секретный ключ для тестов
  static Future<paseto.SecretKey> generateSecretKey(int length) async {
    final bytes = Uint8List(length);
    for (var i = 0; i < length; i++) {
      bytes[i] = i % 256;
    }
    return paseto.SecretKeyData(bytes.toList());
  }

  /// Генерирует предсказуемый nonce для тестов
  static List<int> generateTestNonce(int length) {
    final nonce = Uint8List(length);
    for (var i = 0; i < length; i++) {
      nonce[i] = (i + 100) % 256;
    }
    return nonce.toList();
  }

  /// Создает JSON пакет для тестов
  static paseto.Package createJsonPackage({String? footer}) {
    final jsonData = {'data': 'This is a signed message', 'exp': '2039-01-01T00:00:00+00:00'};
    final jsonString = jsonEncode(jsonData);

    final footerBytes = footer != null ? utf8.encode(footer) : null;
    return paseto.Package(
      content: utf8.encode(jsonString),
      footer: footerBytes,
    );
  }

  /// Создает текстовый пакет для тестов
  static paseto.Package createTextPackage(String text, {String? footer}) {
    final footerBytes = footer != null ? utf8.encode(footer) : null;
    return paseto.Package(
      content: utf8.encode(text),
      footer: footerBytes,
    );
  }

  /// Генерирует ключевую пару для тестов
  static Future<paseto.KeyPair> generateKeyPair(TestKeyPairType keyType) async {
    // Placeholder implementation for tests
    switch (keyType) {
      case TestKeyPairType.ed25519:
        // Используем библиотеку ed25519_edwards для генерации корректной пары ключей
        final edKeyPair = ed.generateKey();
        return paseto.KeyPair(
          privateKey: paseto.SecretKeyData(edKeyPair.privateKey.bytes),
          publicKey: paseto.PublicKeyData(edKeyPair.publicKey.bytes),
          keyType: paseto.KeyPairType.ed25519,
        );

      case TestKeyPairType.ecdsa384:
        // Создаем 96-байтный публичный ключ (48 + 48) для x и y координат
        final privateKeyBytes = Uint8List(48);
        for (var i = 0; i < 48; i++) {
          privateKeyBytes[i] = i;
        }

        // Публичный ключ должен быть 96 байт для ECDSA P-384 (X и Y координаты)
        final publicKeyBytes = Uint8List(96);
        for (var i = 0; i < 48; i++) {
          // Первая часть - X координата
          publicKeyBytes[i] = 48 + i;
          // Вторая часть - Y координата
          publicKeyBytes[i + 48] = 96 + i;
        }

        return paseto.KeyPair(
          privateKey: paseto.SecretKeyData(privateKeyBytes.toList()),
          publicKey: paseto.PublicKeyData(publicKeyBytes.toList()),
          keyType: paseto.KeyPairType.ecdsa384,
        );

      case TestKeyPairType.ecdsa521:
        final privateKeyBytes = Uint8List(66);
        for (var i = 0; i < 66; i++) {
          privateKeyBytes[i] = i;
        }
        final publicKeyBytes = Uint8List(66);
        for (var i = 0; i < 66; i++) {
          publicKeyBytes[i] = 66 + i;
        }
        return paseto.KeyPair(
          privateKey: paseto.SecretKeyData(privateKeyBytes.toList()),
          publicKey: paseto.PublicKeyData(publicKeyBytes.toList()),
          keyType: paseto.KeyPairType.other,
        );
    }
  }

  /// Создает SecretKeyData из HEX-строки
  static paseto.SecretKeyData secretKeyFromHexString(String hexString) {
    final bytes = <int>[];
    for (var i = 0; i < hexString.length; i += 2) {
      bytes.add(int.parse(hexString.substring(i, i + 2), radix: 16));
    }
    return paseto.SecretKeyData(bytes);
  }
}
