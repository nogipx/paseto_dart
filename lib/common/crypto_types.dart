import 'package:meta/meta.dart';
import 'package:paseto_dart/common/version.dart';

/// Типы ключевых пар PASETO
enum KeyPairType {
  /// Ed25519 - используется в v2.public и v4.public
  ed25519,

  /// ECDSA P-384 - используется в v3.public
  ecdsa384,

  /// RSA - используется в v1.public (не реализовано)
  rsa,

  /// Другой алгоритм (для совместимости)
  other,
}

/// Базовый класс для секретных ключей
@immutable
abstract class SecretKey {
  const SecretKey();

  /// Получить данные ключа в виде списка байтов
  Future<List<int>> extractBytes();
}

/// Реализация SecretKey с хранением байтов в памяти
@immutable
class SecretKeyData extends SecretKey {
  const SecretKeyData(this.bytes);

  /// Создает ключ из HEX-строки
  static SecretKeyData fromHexString(String hexString) {
    if (hexString.length % 2 != 0) {
      throw ArgumentError('Hex string must have an even number of characters');
    }

    final result = <int>[];
    for (var i = 0; i < hexString.length; i += 2) {
      final hexByte = hexString.substring(i, i + 2);
      final byte = int.parse(hexByte, radix: 16);
      result.add(byte);
    }

    return SecretKeyData(result);
  }

  /// Байты ключа
  final List<int> bytes;

  @override
  Future<List<int>> extractBytes() async {
    return bytes;
  }

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! SecretKeyData) return false;

    if (bytes.length != other.bytes.length) return false;

    for (var i = 0; i < bytes.length; i++) {
      if (bytes[i] != other.bytes[i]) return false;
    }

    return true;
  }

  @override
  int get hashCode => Object.hashAll(bytes);
}

/// Базовый класс для публичных ключей
@immutable
abstract class PublicKey {
  const PublicKey();

  /// Получить данные ключа в виде списка байтов
  Future<List<int>> get bytes;
}

/// Реализация PublicKey с хранением байтов в памяти
@immutable
class PublicKeyData extends PublicKey {
  const PublicKeyData(this._bytes);

  final List<int> _bytes;

  @override
  Future<List<int>> get bytes async => _bytes;

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! PublicKeyData) return false;

    if (_bytes.length != other._bytes.length) return false;

    for (var i = 0; i < _bytes.length; i++) {
      if (_bytes[i] != other._bytes[i]) return false;
    }

    return true;
  }

  @override
  int get hashCode => Object.hashAll(_bytes);
}

/// Пара ключей: публичный и приватный
@immutable
class KeyPair {
  const KeyPair({
    required this.publicKey,
    required this.privateKey,
    this.keyType = KeyPairType.other,
  });

  final PublicKey publicKey;
  final SecretKey privateKey;
  final KeyPairType keyType;

  /// Тип ключевой пары
  KeyPairType get type => keyType;
}

/// Класс, представляющий сообщение аутентификации (MAC)
@immutable
class Mac {
  const Mac(this.bytes);

  /// Пустой MAC
  static const empty = Mac([]);

  /// Байты MAC
  final List<int> bytes;

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

/// Класс, представляющий хеш данных
@immutable
class Hash {
  const Hash(this.bytes);

  /// Байты хеша
  final List<int> bytes;

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! Hash) return false;

    if (bytes.length != other.bytes.length) return false;

    for (var i = 0; i < bytes.length; i++) {
      if (bytes[i] != other.bytes[i]) return false;
    }

    return true;
  }

  @override
  int get hashCode => Object.hashAll(bytes);
}

/// Класс, представляющий зашифрованные данные
@immutable
class SecretBox {
  const SecretBox(
    this.cipherText, {
    required this.nonce,
    required this.mac,
  });

  /// Создает SecretBox из конкатенированных данных
  factory SecretBox.fromConcatenation(
    List<int> concatenation, {
    required int nonceLength,
    required int macLength,
  }) {
    final cipherTextLength = concatenation.length - nonceLength - macLength;

    if (cipherTextLength < 0) {
      throw ArgumentError(
        'Concatenation too short: ${concatenation.length} bytes, '
        'nonce: $nonceLength bytes, mac: $macLength bytes',
      );
    }

    final nonce = concatenation.sublist(0, nonceLength);
    final cipherText = concatenation.sublist(
      nonceLength,
      nonceLength + cipherTextLength,
    );
    final mac = concatenation.sublist(
      nonceLength + cipherTextLength,
    );

    return SecretBox(
      cipherText,
      nonce: nonce,
      mac: Mac(mac),
    );
  }

  /// Шифротекст
  final List<int> cipherText;

  /// Nonce для шифрования
  final List<int> nonce;

  /// MAC для проверки целостности
  final Mac mac;

  /// Создает новый SecretBox с другим nonce
  SecretBox withNonce(List<int> newNonce) {
    return SecretBox(
      cipherText,
      nonce: newNonce,
      mac: mac,
    );
  }

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! SecretBox) return false;

    if (cipherText.length != other.cipherText.length || nonce.length != other.nonce.length) {
      return false;
    }

    for (var i = 0; i < cipherText.length; i++) {
      if (cipherText[i] != other.cipherText[i]) return false;
    }

    for (var i = 0; i < nonce.length; i++) {
      if (nonce[i] != other.nonce[i]) return false;
    }

    return mac == other.mac;
  }

  @override
  int get hashCode => Object.hash(
        Object.hashAll(cipherText),
        Object.hashAll(nonce),
        mac,
      );
}

/// Расширение для SecretKey, добавляющее методы для валидации.
extension SecretKeyValidation on SecretKey {
  /// Проверяет допустимость ключа для указанной версии PASETO.
  Future<bool> isValidForVersion(Version version) async {
    final bytes = await extractBytes();

    switch (version) {
      case Version.v2:
        // v2.local использует XChaCha20-Poly1305, требует ключ длиной 32 байта
        return bytes.length == 32;
      case Version.v3:
        // v3.local использует AES-256-CTR, требует ключ длиной 32 байта
        return bytes.length == 32;
      case Version.v4:
        // v4.local использует XChaCha20-Poly1305 с BLAKE2b, требует ключ длиной 32 байта
        return bytes.length == 32;
    }
  }

  /// Валидирует ключ для указанной версии PASETO и выбрасывает исключение,
  /// если ключ не соответствует требованиям.
  Future<void> validateForVersion(Version version) async {
    if (!await isValidForVersion(version)) {
      final bytes = await extractBytes();
      throw FormatException(
        'Invalid key length for ${version.name}.local: expected 32 bytes, got ${bytes.length}',
      );
    }
  }
}

/// Расширение для KeyPair, добавляющее методы для валидации.
extension KeyPairValidation on KeyPair {
  /// Проверяет допустимость ключевой пары для указанной версии PASETO.
  Future<bool> isValidForVersion(Version version) async {
    final type = this.type;

    switch (version) {
      case Version.v2:
        // v2.public использует Ed25519
        return type == KeyPairType.ed25519;
      case Version.v3:
        // v3.public использует ECDSA P-384
        return type == KeyPairType.ecdsa384;
      case Version.v4:
        // v4.public использует Ed25519
        return type == KeyPairType.ed25519;
    }
  }

  /// Валидирует ключевую пару для указанной версии PASETO и выбрасывает исключение,
  /// если ключевая пара не соответствует требованиям.
  Future<void> validateForVersion(Version version) async {
    if (!await isValidForVersion(version)) {
      throw FormatException(
        'Invalid key pair type for ${version.name}.public: expected ${_getExpectedKeyType(version)}, got $type',
      );
    }
  }

  /// Возвращает ожидаемый тип ключа для указанной версии.
  KeyPairType _getExpectedKeyType(Version version) {
    switch (version) {
      case Version.v2:
      case Version.v4:
        return KeyPairType.ed25519;
      case Version.v3:
        return KeyPairType.ecdsa384;
      // по умолчанию используем Ed25519
    }
  }
}
