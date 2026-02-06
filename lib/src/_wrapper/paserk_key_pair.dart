// SPDX-FileCopyrightText: 2026 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: MIT

part of '_index.dart';

/// Обёртка пары Ed25519 с возможностью очистки seed.
class PaserkKeyPair {
  PaserkKeyPair._(this._secret);

  static Future<PaserkKeyPair> _fromKeyPair(SimpleKeyPair pair) async {
    final secret = await pair.extract();
    final publicKey = await pair.extractPublicKey();
    final bytes = Uint8List(K4SecretKey.keyLength)
      ..setAll(0, secret.bytes)
      ..setAll(secret.bytes.length, publicKey.bytes);
    return PaserkKeyPair._(K4SecretKey(bytes));
  }

  final K4SecretKey _secret;
  bool _disposed = false;

  /// Возвращает PASERK `k4.secret` строку.
  String toPaserk() {
    _ensureActive();
    return _secret.toString();
  }

  /// Возвращает PASERK-идентификатор (k4.sid).
  String get identifier {
    _ensureActive();
    return K4Sid.fromKey(_secret).toString();
  }

  /// Возвращает публичный ключ в PASERK `k4.public` формате.
  String get publicPaserk => publicKey.toPaserk();

  /// Возвращает PASERK-идентификатор публичного ключа (k4.pid).
  String get publicIdentifier => publicKey.identifier;

  /// Возвращает обёртку публичного ключа.
  PaserkPublicKey get publicKey {
    _ensureActive();
    return PaserkPublicKey._(K4PublicKey(_secret.publicKeyBytes));
  }

  /// Обнуляет seed и публичную часть. После вызова объект использовать нельзя.
  void dispose() {
    if (_disposed) return;
    _zero(_secret.rawBytes);
    _disposed = true;
  }

  /// Упаковывает секретный ключ в `k4.secret-pw`.
  Future<String> toPasswordPaserk({
    required String password,
    int memoryCost = K4SecretPw.defaultMemoryCost,
    int timeCost = K4SecretPw.defaultTimeCost,
    int parallelism = K4SecretPw.defaultParallelism,
  }) async {
    _ensureActive();
    final wrapped = await K4SecretPw.wrap(
      _secret,
      password,
      memoryCost: memoryCost,
      timeCost: timeCost,
      parallelism: parallelism,
    );
    return wrapped.toString();
  }

  /// Восстанавливает пару ключей из `k4.secret-pw`.
  static Future<PaserkKeyPair> fromPasswordPaserk({
    required String paserk,
    required String password,
  }) async {
    final key = await K4SecretPw.unwrap(paserk, password);
    return PaserkKeyPair._(key);
  }

  /// Упаковывает секретный ключ в `k4.secret-wrap.pie`.
  String toWrappedPaserk({required PaserkSymmetricKey wrappingKey}) {
    _ensureActive();
    wrappingKey._ensureActive();
    final wrapped = K4SecretWrap.wrap(_secret, wrappingKey._key);
    return wrapped.toString();
  }

  /// Распаковывает `k4.secret-wrap.pie` строку.
  static PaserkKeyPair fromWrappedPaserk({
    required String paserk,
    required PaserkSymmetricKey wrappingKey,
  }) {
    final key = K4SecretWrap.unwrap(paserk, wrappingKey._key);
    return PaserkKeyPair._(key);
  }

  /// Возвращает PASERK идентификатор (k4.sid) для секретного ключа.
  String get identifierSecret => identifier;

  /// Возвращает идентификатор публичного ключа (k4.pid).
  String get identifierPublic => publicIdentifier;

  /// Выполняет действие с временным SimpleKeyPair и, опционально, диспоузит ключ.
  Future<T> withKeyPair<T>(
    Future<T> Function(SimpleKeyPair pair) action, {
    bool disposeAfter = false,
  }) async {
    try {
      return await _useKeyPair(action);
    } finally {
      if (disposeAfter) {
        dispose();
      }
    }
  }

  /// Преобразует секретный ключ в `k4.secret-pw` строку.
  Future<T> _useKeyPair<T>(
      Future<T> Function(SimpleKeyPair pair) action) async {
    _ensureActive();
    final seed = Uint8List.fromList(_secret.rawBytes.sublist(0, 32));
    try {
      final pair = await Ed25519().newKeyPairFromSeed(seed);
      return await action(pair);
    } finally {
      _zero(seed);
    }
  }

  void _ensureActive() {
    if (_disposed) {
      throw StateError('The key pair has been disposed');
    }
  }
}
