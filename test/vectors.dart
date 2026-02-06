import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:paseto_dart/paseto_dart.dart';

const _officialVectorsRoot = 'test/test-vectors-master';

String _officialPath(String relative) => '$_officialVectorsRoot/$relative';

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

  List<LocalVector> get localSuccess =>
      local.where((vector) => !vector.expectFail).toList(growable: false);

  List<LocalVector> get localFailures =>
      local.where((vector) => vector.expectFail).toList(growable: false);

  List<PublicVector> get publicSuccess => public
      .where((vector) => !vector.expectFail && vector.hasPublicKey)
      .toList(growable: false);

  List<PublicVector> get publicFailures =>
      public.where((vector) => vector.expectFail).toList(growable: false);

  factory Vectors.fromJsonFile(Version version, String filePath) {
    final file = File(filePath);
    if (!file.existsSync()) {
      throw StateError(
        'Missing official PASETO vectors at "$filePath". '
        'Ensure the test/test-vectors-master repository is available.',
      );
    }

    final fileContent = file.readAsStringSync();
    final json = jsonDecode(fileContent) as Map<String, dynamic>;

    final name = json['name'] as String? ?? 'unknown';
    final testsJson = json['tests'] as List<dynamic>? ?? const [];

    final local = <LocalVector>[];
    final public = <PublicVector>[];

    for (final testJson in testsJson) {
      final map = testJson as Map<String, dynamic>;
      final token = map['token'] as String? ?? '';
      final isLocal = token.contains('.local.');
      final isPublic = token.contains('.public.');

      if (isLocal) {
        local.add(LocalVector.fromJson(map));
      } else if (isPublic) {
        public.add(PublicVector.fromJson(map));
      }
    }

    return Vectors(version: version, name: name, local: local, public: public);
  }

  /// Загружает тестовые векторы для PASETO v4 из официального репозитория.
  static Vectors loadV4() {
    return Vectors.fromJsonFile(Version.v4, _officialPath('v4.json'));
  }
}

class PaserkVectors {
  final Map<String, List<PaserkVector>> _byType;

  PaserkVectors._(this._byType);

  Iterable<PaserkVector> byType(String type) =>
      _byType[type] ?? const <PaserkVector>[];

  factory PaserkVectors.fromOfficialFiles(Map<String, String> filesByType) {
    final data = <String, List<PaserkVector>>{};

    filesByType.forEach((type, relativePath) {
      final file = File(_officialPath(relativePath));
      if (!file.existsSync()) {
        throw StateError(
          'Missing official PASERK vectors at "${file.path}". '
          'Ensure the test/test-vectors-master repository is available.',
        );
      }

      final json = jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
      final tests = json['tests'] as List<dynamic>? ?? const [];

      final list = data.putIfAbsent(type, () => <PaserkVector>[]);
      for (final test in tests) {
        list.add(PaserkVector.fromOfficial(type, test as Map<String, dynamic>));
      }
    });

    return PaserkVectors._({
      for (final entry in data.entries)
        entry.key: List<PaserkVector>.unmodifiable(entry.value),
    });
  }

  static PaserkVectors loadK4() {
    return PaserkVectors.fromOfficialFiles({
      'k4.local': 'PASERK/k4.local.json',
      'k4.secret': 'PASERK/k4.secret.json',
      'k4.public': 'PASERK/k4.public.json',
      'k4.local-wrap.pie': 'PASERK/k4.local-wrap.pie.json',
      'k4.secret-wrap.pie': 'PASERK/k4.secret-wrap.pie.json',
      'k4.local-pw': 'PASERK/k4.local-pw.json',
      'k4.secret-pw': 'PASERK/k4.secret-pw.json',
      'k4.seal': 'PASERK/k4.seal.json',
      'k4.lid': 'PASERK/k4.lid.json',
      'k4.pid': 'PASERK/k4.pid.json',
      'k4.sid': 'PASERK/k4.sid.json',
    });
  }
}

final class PaserkVector {
  final String type;
  final String name;
  final bool expectFail;
  final String? comment;
  final Map<String, dynamic> data;

  PaserkVector({
    required this.type,
    required this.name,
    required this.expectFail,
    required this.data,
    this.comment,
  });

  factory PaserkVector.fromOfficial(String type, Map<String, dynamic> json) {
    final name = json['name'] as String?;
    if (name == null || name.isEmpty) {
      throw ArgumentError.value(name, 'name', 'Expected non-empty string');
    }

    final expectFail = json['expect-fail'] as bool? ?? false;
    final comment = json['comment'] as String?;

    final data = Map<String, dynamic>.from(json)
      ..remove('name')
      ..remove('expect-fail')
      ..remove('comment');

    return PaserkVector(
      type: type,
      name: name,
      expectFail: expectFail,
      data: data,
      comment: comment,
    );
  }

  T require<T>(String key) {
    final value = data[key];
    if (value is! T) {
      throw StateError(
        'Expected "$key" to be a ${T.toString()} in $type vector "$name"',
      );
    }
    return value;
  }

  String requireString(String key) => require<String>(key);

  String? optionalString(String key) => data[key] as String?;
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

  bool get hasPayload => payload != null;

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

  Uint8List? get footerBytes {
    return footer.isNotEmpty ? utf8.encode(footer) : null;
  }

  Uint8List? get payloadBytes {
    return payload != null ? utf8.encode(payload!) : null;
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
      secretKey: (json['secret-key'] as String?) ?? (json['key'] as String?),
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

  Uint8List? get footerBytes {
    return footer.isNotEmpty ? utf8.encode(footer) : null;
  }

  Uint8List? get payloadBytes {
    return payload != null ? utf8.encode(payload!) : null;
  }
}

/// Преобразует строку с шестнадцатеричным представлением в Uint8List
Uint8List hexToUint8List(String hex) {
  final cleanHex = hex.replaceAll(' ', '').toLowerCase();

  if (cleanHex.isEmpty) {
    return Uint8List(0);
  }

  final paddedHex = cleanHex.length % 2 == 0 ? cleanHex : '0$cleanHex';

  final buffer = Uint8List(paddedHex.length ~/ 2);

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
    if (includeSpaces && i > 0) {
      buffer.write(' ');
    }
    buffer.write(bytes[i].toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
}
