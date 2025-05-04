import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:paseto_dart/paseto_dart.dart';
import 'test_utils.dart';

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
  PublicKeyData? get publicKeyData {
    return publicKey != null ? PublicKeyData(hexToUint8List(publicKey!)) : null;
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
