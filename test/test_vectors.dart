import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:paseto_dart/paseto_dart.dart';

import 'test_utils.dart';

/// Класс, представляющий набор тестовых векторов
class PasetoTestVectors {
  final String name;
  final List<PasetoTestVector> tests;

  PasetoTestVectors({required this.name, required this.tests});

  /// Загружает тестовые векторы из JSON-файла
  static PasetoTestVectors fromJsonFile(String filePath) {
    final fileContent = File(filePath).readAsStringSync();
    final json = jsonDecode(fileContent) as Map<String, dynamic>;

    final name = json['name'] as String;
    final testsJson = json['tests'] as List<dynamic>;

    final tests = testsJson.map((testJson) {
      final testName = testJson['name'] as String;

      // Определяем тип вектора по имени
      if (testName.startsWith('4-E-') ||
          (testName.startsWith('4-F-') &&
              testJson['token'].toString().startsWith('v4.local.'))) {
        return LocalTestVector.fromJson(testJson);
      } else if (testName.startsWith('4-S-') ||
          (testName.startsWith('4-F-') &&
              testJson['token'].toString().startsWith('v4.public.'))) {
        return PublicTestVector.fromJson(testJson);
      } else {
        // Общий случай для других типов тестов
        return PasetoTestVector.fromJson(testJson);
      }
    }).toList();

    return PasetoTestVectors(name: name, tests: tests);
  }

  /// Получает все локальные тестовые векторы
  List<LocalTestVector> get localVectors {
    return tests.whereType<LocalTestVector>().toList();
  }

  /// Получает все публичные тестовые векторы
  List<PublicTestVector> get publicVectors {
    return tests.whereType<PublicTestVector>().toList();
  }

  /// Получает все успешные тестовые векторы
  List<PasetoTestVector> get successVectors {
    return tests.where((test) => !test.expectFail).toList();
  }

  /// Получает все тестовые векторы с ожидаемой ошибкой
  List<PasetoTestVector> get failVectors {
    return tests.where((test) => test.expectFail).toList();
  }
}

/// Базовый класс для тестового вектора PASETO
class PasetoTestVector {
  final String name;
  final bool expectFail;
  final String token;
  final String? payload;
  final String footer;
  final String implicitAssertion;

  PasetoTestVector({
    required this.name,
    required this.expectFail,
    required this.token,
    this.payload,
    required this.footer,
    required this.implicitAssertion,
  });

  factory PasetoTestVector.fromJson(Map<String, dynamic> json) {
    return PasetoTestVector(
      name: json['name'] as String,
      expectFail: json['expect-fail'] as bool,
      token: json['token'] as String,
      payload: json['payload'] as String?,
      footer: json['footer'] as String? ?? '',
      implicitAssertion: json['implicit-assertion'] as String? ?? '',
    );
  }

  /// Получает байты footer
  Uint8List? get footerBytes {
    return footer.isNotEmpty ? utf8.encode(footer) : null;
  }

  /// Получает байты implicit assertion
  Uint8List? get implicitBytes {
    return implicitAssertion.isNotEmpty ? utf8.encode(implicitAssertion) : null;
  }

  /// Проверяет, что токен имеет ожидаемый префикс версии
  bool hasCorrectVersionPrefix(String expectedPrefix) {
    return token.startsWith(expectedPrefix);
  }
}

/// Класс для тестового вектора типа local
class LocalTestVector extends PasetoTestVector {
  final String key;
  final String? nonce;

  LocalTestVector({
    required super.name,
    required super.expectFail,
    required super.token,
    super.payload,
    required super.footer,
    required super.implicitAssertion,
    required this.key,
    this.nonce,
  });

  factory LocalTestVector.fromJson(Map<String, dynamic> json) {
    return LocalTestVector(
      name: json['name'] as String,
      expectFail: json['expect-fail'] as bool,
      token: json['token'] as String,
      payload: json['payload'] as String?,
      footer: json['footer'] as String? ?? '',
      implicitAssertion: json['implicit-assertion'] as String? ?? '',
      key: json['key'] as String,
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
      footer: footerBytes,
    );
  }
}

/// Класс для тестового вектора типа public
class PublicTestVector extends PasetoTestVector {
  final String? publicKey;
  final String? secretKey;
  final String? secretKeySeed;
  final String? secretKeyPem;
  final String? publicKeyPem;

  PublicTestVector({
    required super.name,
    required super.expectFail,
    required super.token,
    super.payload,
    required super.footer,
    required super.implicitAssertion,
    this.publicKey,
    this.secretKey,
    this.secretKeySeed,
    this.secretKeyPem,
    this.publicKeyPem,
  });

  factory PublicTestVector.fromJson(Map<String, dynamic> json) {
    return PublicTestVector(
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
      footer: footerBytes,
    );
  }
}
