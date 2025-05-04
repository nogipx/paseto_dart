import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:paseto_dart/paseto_dart.dart';

class Vectors {
  final Version version;
  final String name;
  final List<LocalVector> local;
  final List<PublicVector> public;

  Vectors({
    required this.version,
    required this.name,
    required this.local,
    required this.public,
  });

  factory Vectors.fromJsonFile(Version version, String filePath) {
    final file = File(filePath);
    final fileContent = file.readAsStringSync();

    final json = jsonDecode(fileContent) as Map<String, dynamic>;

    final name = json['name'] as String;
    final testsJson = json['tests'] as List<dynamic>;

    final local = <LocalVector>[];
    final public = <PublicVector>[];

    for (final testJson in testsJson) {
      final ver = version.name.replaceAll('v', '');
      final token = testJson['token'] as String;

      final isLocal = token.startsWith('v$ver.local');
      final isPublic = token.startsWith('v$ver.public');

      if (isLocal) {
        local.add(LocalVector.fromJson(testJson));
      } else if (isPublic) {
        public.add(PublicVector.fromJson(testJson));
      }
    }

    return Vectors(name: name, local: local, public: public, version: version);
  }

  /// Загружает тестовые векторы для PASETO v4
  static Vectors loadV4() {
    return Vectors.fromJsonFile(Version.v4, 'test/vectors/v4.json');
  }
}

/// Класс для тестового вектора типа local
final class LocalVector {
  final String key;
  final String? nonce;
  final String name;
  final bool expectFail;
  final String token;
  final String? payload;
  final String footer;
  final String implicitAssertion;

  LocalVector({
    required this.name,
    required this.expectFail,
    required this.token,
    this.payload,
    required this.footer,
    required this.implicitAssertion,
    required this.key,
    this.nonce,
  });

  factory LocalVector.fromJson(Map<String, dynamic> json) {
    return LocalVector(
      name: json['name'] as String,
      expectFail: json['expect-fail'] as bool,
      token: json['token'] as String,
      payload: json['payload'] as String?,
      footer: json['footer'] as String? ?? '',
      implicitAssertion: json['implicit-assertion'] as String? ?? '',
      key: json['key'] as String? ?? '',
      nonce: json['nonce'] as String?,
    );
  }

  /// Получает ключ шифрования как SecretKeyData
  SecretKeyData get secretKey {
    return SecretKeyData(hexToUint8List(key));
  }

  /// Получает nonce как Uint8List (если есть)
  Uint8List? get nonceBytes {
    return nonce != null ? hexToUint8List(nonce!) : null;
  }

  /// Создает Package из payload и footer
  Package get package {
    if (payload == null) {
      throw StateError('Payload is null for test vector $name');
    }

    return Package(
      content: utf8.encode(payload!),
      footer: utf8.encode(footer),
    );
  }

  Uint8List? get implicitAssertionBytes {
    return implicitAssertion.isNotEmpty ? utf8.encode(implicitAssertion) : null;
  }
}

/// Класс для тестового вектора типа public
final class PublicVector {
  final String? publicKey;
  final String? secretKey;
  final String? secretKeySeed;
  final String? secretKeyPem;
  final String? publicKeyPem;
  final String name;
  final bool expectFail;
  final String token;
  final String? payload;
  final String footer;
  final String implicitAssertion;

  PublicVector({
    required this.name,
    required this.expectFail,
    required this.token,
    this.payload,
    required this.footer,
    required this.implicitAssertion,
    this.publicKey,
    this.secretKey,
    this.secretKeySeed,
    this.secretKeyPem,
    this.publicKeyPem,
  });

  factory PublicVector.fromJson(Map<String, dynamic> json) {
    return PublicVector(
      name: json['name'] as String,
      expectFail: json['expect-fail'] as bool,
      token: json['token'] as String,
      payload: json['payload'] as String?,
      footer: json['footer'] as String? ?? '',
      implicitAssertion: json['implicit-assertion'] as String? ?? '',
      publicKey: json['public-key'] as String?,
      secretKey: json['secret-key'] as String?,
      secretKeySeed: json['secret-key-seed'] as String?,
      secretKeyPem: json['secret-key-pem'] as String?,
      publicKeyPem: json['public-key-pem'] as String?,
    );
  }

  /// Проверяет наличие публичного ключа
  bool get hasPublicKey => publicKey != null;

  /// Проверяет наличие секретного ключа
  bool get hasSecretKey => secretKey != null;

  /// Получает публичный ключ как PublicKeyData
  SimplePublicKey? get publicKeyData {
    return publicKey != null
        ? SimplePublicKey(
            hexToUint8List(publicKey!),
            type: KeyPairType.ed25519,
          )
        : null;
  }

  /// Получает секретный ключ как SecretKeyData
  SecretKeyData? get secretKeyData {
    return secretKey != null ? SecretKeyData(hexToUint8List(secretKey!)) : null;
  }

  /// Создает Package из payload и footer
  Package? get package {
    if (payload == null) {
      return null;
    }

    return Package(
      content: utf8.encode(payload!),
      footer: utf8.encode(footer),
    );
  }

  Uint8List? get implicitAssertionBytes {
    return implicitAssertion.isNotEmpty ? utf8.encode(implicitAssertion) : null;
  }
}

/// Преобразует строку с шестнадцатеричным представлением в Uint8List
Uint8List hexToUint8List(String hex) {
  // Убираем пробелы и приводим к нижнему регистру
  final cleanHex = hex.replaceAll(' ', '').toLowerCase();

  if (cleanHex.isEmpty) {
    return Uint8List(0);
  }

  // При необходимости дополняем нулем спереди для четной длины
  final paddedHex = cleanHex.length % 2 == 0 ? cleanHex : '0$cleanHex';

  // Создаем буфер нужного размера
  final buffer = Uint8List(paddedHex.length ~/ 2);

  // Заполняем буфер
  for (var i = 0; i < buffer.length; i++) {
    final byteString = paddedHex.substring(i * 2, i * 2 + 2);
    buffer[i] = int.parse(byteString, radix: 16);
  }

  return buffer;
}

/// Преобразует Uint8List в строку с шестнадцатеричным представлением
String uint8ListToHex(Uint8List bytes, {bool includeSpaces = false}) {
  final buffer = StringBuffer();
  for (var i = 0; i < bytes.length; i++) {
    // Добавляем пробел после каждых 2 символов, если требуется
    if (includeSpaces && i > 0) {
      buffer.write(' ');
    }
    // Преобразуем байт в его шестнадцатеричное представление
    // и дополняем нулем слева при необходимости
    buffer.write(bytes[i].toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
}
