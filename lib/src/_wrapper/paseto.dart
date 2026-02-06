// SPDX-FileCopyrightText: 2026 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: MIT

part of '_index.dart';

/// 🚀 Высокоуровневый фасад для работы с PASETO v4 и PASERK
///
/// Объединяет генерацию ключей, выпуск и проверку токенов, а также
/// преобразования PASERK с аккуратной очисткой чувствительных байтов после
/// использования. Методы возвращают обёртки [PaserkSymmetricKey],
/// [PaserkPublicKey] и [PaserkKeyPair], которые поддерживают `dispose()`
/// ключевого материала в памяти.
abstract interface class Paseto {
  const Paseto._();

  /// Текущая версия пакета
  static const version = '2.0.0';

  // ---------------------------------------------------------------------------
  // Генерация и восстановление ключей
  // ---------------------------------------------------------------------------

  /// Генерирует новый симметричный ключ для v4.local.
  static PaserkSymmetricKey generateSymmetricKey() =>
      PaserkSymmetricKey._(K4LocalKey.generate());

  /// Генерирует криптографическую соль для PBKW.
  static PaserkSalt generatePasswordSalt(
          {int length = PaserkSalt.defaultLength}) =>
      PaserkSalt.generate(length: length);

  /// Генерирует криптографически стойкий NanoID (совместим с licensify).
  static String nanoId({
    int size = NanoId.defaultSize,
    String alphabet = NanoId.defaultAlphabet,
  }) =>
      NanoId.generate(size: size, alphabet: alphabet);

  /// Генерирует новую пару ключей Ed25519 для v4.public.
  static Future<PaserkKeyPair> generateKeyPair() async {
    final pair = await Ed25519().newKeyPair();
    return PaserkKeyPair._fromKeyPair(pair);
  }

  /// Создаёт симметричный ключ из PASERK `k4.local` строки.
  static PaserkSymmetricKey symmetricKeyFromPaserk(String paserk) =>
      PaserkSymmetricKey._(K4LocalKey.fromString(paserk));

  /// Создаёт симметричный ключ из сырых байтов.
  static PaserkSymmetricKey symmetricKeyFromBytes(List<int> keyBytes) =>
      PaserkSymmetricKey._(K4LocalKey(Uint8List.fromList(keyBytes)));

  /// Преобразует симметричный ключ в PASERK k4.local строку.
  static String symmetricKeyToPaserk(PaserkSymmetricKey key) => key.toPaserk();

  /// Возвращает PASERK идентификатор (k4.lid) для симметричного ключа.
  static String symmetricKeyIdentifier(PaserkSymmetricKey key) =>
      key.identifier;

  /// Создаёт симметричный ключ из `k4.local-pw` с паролем.
  static Future<PaserkSymmetricKey> symmetricKeyFromPaserkPassword({
    required String paserk,
    required String password,
  }) =>
      PaserkSymmetricKey.fromPasswordPaserk(
        paserk: paserk,
        password: password,
      );

  /// Создаёт симметричный ключ из пароля и соли (детерминированно).
  static Future<PaserkSymmetricKey> symmetricKeyFromPassword({
    required String password,
    required PaserkSalt salt,
    int memoryCost = K4LocalPw.defaultMemoryCost,
    int timeCost = K4LocalPw.defaultTimeCost,
    int parallelism = K4LocalPw.defaultParallelism,
  }) async {
    final algorithm = Argon2id(
      memory: memoryCost ~/ 1024,
      iterations: timeCost,
      parallelism: parallelism,
      hashLength: K4LocalKey.keyLength,
    );
    final secret = await algorithm.deriveKeyFromPassword(
      password: password,
      nonce: salt.bytes,
    );
    final keyBytes = await secret.extractBytes();
    return PaserkSymmetricKey._(K4LocalKey(Uint8List.fromList(keyBytes)));
  }

  /// Преобразует симметричный ключ в `k4.local-pw`.
  static Future<String> symmetricKeyToPaserkPassword({
    required PaserkSymmetricKey key,
    required String password,
    int memoryCost = K4LocalPw.defaultMemoryCost,
    int timeCost = K4LocalPw.defaultTimeCost,
    int parallelism = K4LocalPw.defaultParallelism,
  }) =>
      key.toPasswordPaserk(
        password: password,
        memoryCost: memoryCost,
        timeCost: timeCost,
        parallelism: parallelism,
      );

  /// Преобразует симметричный ключ в `k4.local-wrap.pie`.
  static String symmetricKeyToPaserkWrap({
    required PaserkSymmetricKey key,
    required PaserkSymmetricKey wrappingKey,
  }) =>
      key.toWrappedPaserk(wrappingKey: wrappingKey);

  /// Восстанавливает симметричный ключ из `k4.local-wrap.pie`.
  static PaserkSymmetricKey symmetricKeyFromPaserkWrap({
    required String paserk,
    required PaserkSymmetricKey wrappingKey,
  }) =>
      PaserkSymmetricKey.fromWrappedPaserk(
        paserk: paserk,
        wrappingKey: wrappingKey,
      );

  /// Запечатывает симметричный ключ -> `k4.seal`.
  static Future<String> symmetricKeyToPaserkSeal({
    required PaserkSymmetricKey key,
    required PaserkPublicKey publicKey,
  }) =>
      key.toSealedPaserk(publicKey: publicKey);

  /// Распечатывает `k4.seal`.
  static Future<PaserkSymmetricKey> symmetricKeyFromPaserkSeal({
    required String paserk,
    required PaserkKeyPair keyPair,
  }) =>
      PaserkSymmetricKey.fromSealedPaserk(
        paserk: paserk,
        keyPair: keyPair,
      );

  /// Создаёт пару ключей подписи из PASERK `k4.secret` строки.
  static PaserkKeyPair keyPairFromPaserk(String paserk) =>
      PaserkKeyPair._(K4SecretKey.fromString(paserk));

  /// Создаёт пару ключей из байтов (seed+pubkey или сырой 64‑байтный ключ).
  static PaserkKeyPair keyPairFromBytes({
    required List<int> privateKeyBytes,
    required List<int> publicKeyBytes,
  }) {
    final combined = Uint8List(K4SecretKey.keyLength)
      ..setAll(0, privateKeyBytes)
      ..setAll(privateKeyBytes.length, publicKeyBytes);
    return PaserkKeyPair._(K4SecretKey(combined));
  }

  /// Преобразует пару ключей в PASERK k4.secret строку.
  static String keyPairToPaserk(PaserkKeyPair keyPair) => keyPair.toPaserk();

  /// Возвращает идентификатор секретного ключа (k4.sid).
  static String keyPairIdentifier(PaserkKeyPair keyPair) => keyPair.identifier;

  /// Возвращает публичный PASERK (k4.public).
  static String keyPairPublicPaserk(PaserkKeyPair keyPair) =>
      keyPair.publicPaserk;

  /// Возвращает публичный идентификатор (k4.pid).
  static String keyPairPublicIdentifier(PaserkKeyPair keyPair) =>
      keyPair.publicIdentifier;

  /// Создаёт публичный ключ из PASERK `k4.public`.
  static PaserkPublicKey publicKeyFromPaserk(String paserk) =>
      PaserkPublicKey.fromPaserk(paserk);

  /// Возвращает публичный идентификатор (k4.pid) для переданного публичного ключа.
  static String publicKeyIdentifier(PaserkPublicKey key) => key.identifier;

  /// Восстанавливает пару ключей из `k4.secret-pw`.
  static Future<PaserkKeyPair> keyPairFromPaserkPassword({
    required String paserk,
    required String password,
  }) =>
      PaserkKeyPair.fromPasswordPaserk(paserk: paserk, password: password);

  /// Преобразует секретный ключ в `k4.secret-pw`.
  static Future<String> keyPairToPaserkPassword({
    required PaserkKeyPair keyPair,
    required String password,
    int memoryCost = K4SecretPw.defaultMemoryCost,
    int timeCost = K4SecretPw.defaultTimeCost,
    int parallelism = K4SecretPw.defaultParallelism,
  }) =>
      keyPair.toPasswordPaserk(
        password: password,
        memoryCost: memoryCost,
        timeCost: timeCost,
        parallelism: parallelism,
      );

  /// Преобразует секретный ключ в `k4.secret-wrap.pie`.
  static String keyPairToPaserkWrap({
    required PaserkKeyPair keyPair,
    required PaserkSymmetricKey wrappingKey,
  }) =>
      keyPair.toWrappedPaserk(wrappingKey: wrappingKey);

  /// Восстанавливает пару из `k4.secret-wrap.pie`.
  static PaserkKeyPair keyPairFromPaserkWrap({
    required String paserk,
    required PaserkSymmetricKey wrappingKey,
  }) =>
      PaserkKeyPair.fromWrappedPaserk(
        paserk: paserk,
        wrappingKey: wrappingKey,
      );

  // ---------------------------------------------------------------------------
  // Подпись и проверка (v4.public)
  // ---------------------------------------------------------------------------

  /// Подписывает JSON payload в PASETO v4.public токен.
  static Future<String> signPublicToken({
    required Map<String, dynamic> payload,
    required PaserkKeyPair keyPair,
    String? footer,
    String? implicitAssertion,
  }) async {
    return keyPair._useKeyPair((simplePair) async {
      final footerBytes = footer != null ? utf8.encode(footer) : null;
      final implicitBytes =
          implicitAssertion != null ? utf8.encode(implicitAssertion) : null;

      final package = Package(
        content: utf8.encode(jsonEncode(payload)),
        footer: footerBytes,
      );

      final signedPayload = await PublicV4.sign(
        package,
        keyPair: simplePair,
        implicit: implicitBytes,
      );

      final token = Token(
        header: PublicV4.header,
        payload: signedPayload,
        footer: footerBytes,
      );

      return token.toTokenString;
    });
  }

  /// Проверяет PASETO v4.public токен и возвращает расшифрованный payload.
  static Future<Map<String, dynamic>> verifyPublicToken({
    required String token,
    required PaserkPublicKey publicKey,
    String? implicitAssertion,
  }) async {
    final parsed = await Token.fromString(token);
    final implicitBytes =
        implicitAssertion != null ? utf8.encode(implicitAssertion) : null;

    final message = await parsed.verifyPublicMessage(
      publicKey: await publicKey._asSimple(),
      implicit: implicitBytes,
    );

    return _decodePayload(message.package.content);
  }

  /// Проверяет токен, используя PASERK `k4.public` строку.
  static Future<Map<String, dynamic>> verifyPublicTokenWithPaserk({
    required String token,
    required String publicPaserk,
    String? implicitAssertion,
  }) async {
    return verifyPublicToken(
      token: token,
      publicKey: PaserkPublicKey.fromPaserk(publicPaserk),
      implicitAssertion: implicitAssertion,
    );
  }

  // ---------------------------------------------------------------------------
  // Шифрование и расшифровка (v4.local)
  // ---------------------------------------------------------------------------

  /// Шифрует JSON payload в PASETO v4.local токен.
  static Future<String> encryptLocal({
    required Map<String, dynamic> payload,
    required PaserkSymmetricKey key,
    String? footer,
    String? implicitAssertion,
  }) async {
    return key._useSecretKey((secretKey) async {
      final footerBytes = footer != null ? utf8.encode(footer) : null;
      final implicitBytes =
          implicitAssertion != null ? utf8.encode(implicitAssertion) : null;

      final package = Package(
        content: utf8.encode(jsonEncode(payload)),
        footer: footerBytes,
      );

      final payloadEncrypted = await LocalV4.encrypt(
        package,
        secretKey: secretKey,
        implicit: implicitBytes,
      );

      final token = Token(
        header: LocalV4.header,
        payload: payloadEncrypted,
        footer: footerBytes,
      );

      return token.toTokenString;
    });
  }

  /// Расшифровывает PASETO v4.local токен в Map.
  static Future<Map<String, dynamic>> decryptLocal({
    required String token,
    required PaserkSymmetricKey key,
    String? implicitAssertion,
  }) async {
    return key._useSecretKey((secretKey) async {
      final parsed = await Token.fromString(token);
      final implicitBytes =
          implicitAssertion != null ? utf8.encode(implicitAssertion) : null;

      final message = await parsed.decryptLocalMessage(
        secretKey: secretKey,
        implicit: implicitBytes,
      );

      return _decodePayload(message.package.content);
    });
  }

  // ---------------------------------------------------------------------------
  // Служебные утилиты
  // ---------------------------------------------------------------------------

  /// Шифрует данные на публичный ключ получателя (PASETO v4.public seal-flow).
  /// Возвращает v4.local токен, где одноразовый ключ запечатан в footer.
  static Future<String> encryptForPublicKey({
    required Map<String, dynamic> data,
    required PaserkPublicKey publicKey,
    String? footer,
    String? implicitAssertion,
  }) async {
    return _withTempLocalKey((localKey) async {
      // запечатали симметричный ключ
      final sealed = await localKey.toSealedPaserk(publicKey: publicKey);

      // собираем footer заранее, чтобы MAC был корректным
      final footerJson = <String, dynamic>{
        'k4seal': sealed,
        if (footer != null) 'footer': footer,
      };
      final mergedFooter = jsonEncode(footerJson);

      // шифруем локально с уже готовым footer
      return await encryptLocal(
        payload: data,
        key: localKey,
        footer: mergedFooter,
        implicitAssertion: implicitAssertion,
      );
    });
  }

  /// Расшифровывает данные, зашифрованные через [encryptForPublicKey].
  static Future<Map<String, dynamic>> decryptForKeyPair({
    required String token,
    required PaserkKeyPair keyPair,
    String? implicitAssertion,
  }) async {
    keyPair._ensureActive();
    final parsed = await Token.fromString(token);

    // извлечь k4.seal из footer
    final footerBytes = parsed.footer;
    if (footerBytes == null) {
      throw ArgumentError('Missing footer with k4seal');
    }
    Map<String, dynamic> footerJson;
    try {
      footerJson = jsonDecode(utf8.decode(footerBytes)) as Map<String, dynamic>;
    } catch (_) {
      throw ArgumentError('Footer must contain JSON with k4seal');
    }
    final sealed = footerJson['k4seal'] as String?;
    if (sealed == null) {
      throw ArgumentError('k4seal not found in footer');
    }

    // восстановить симметричный ключ
    final localKey = await PaserkSymmetricKey.fromSealedPaserk(
      paserk: sealed,
      keyPair: keyPair,
    );
    try {
      // расшифровать локальный токен
      final message = await parsed.decryptLocalMessage(
        secretKey: await localKey._asSecretKey(),
        implicit:
            implicitAssertion != null ? utf8.encode(implicitAssertion) : null,
      );
      return _decodePayload(message.package.content);
    } finally {
      localKey.dispose();
    }
  }

  /// Проверяет, похоже ли значение на PASERK-строку.
  static bool isPaserk(String value) => PaserkKey.isPaserk(value);

  static Map<String, dynamic> _decodePayload(List<int> bytes) {
    final decoded = utf8.decode(bytes);
    final dynamic json = jsonDecode(decoded);
    if (json is Map<String, dynamic>) return json;
    throw const FormatException('Payload is not a JSON object');
  }

  static Future<T> _withTempLocalKey<T>(
    Future<T> Function(PaserkSymmetricKey key) body,
  ) async {
    final key = generateSymmetricKey();
    try {
      return await body(key);
    } finally {
      key.dispose();
    }
  }
}
