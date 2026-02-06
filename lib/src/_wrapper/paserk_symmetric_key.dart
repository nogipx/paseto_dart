// SPDX-FileCopyrightText: 2026 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: MIT

part of '_index.dart';

/// Обёртка симметричного ключа v4.local с ручным `dispose()`.
final class PaserkSymmetricKey {
  PaserkSymmetricKey._(this._key);

  final K4LocalKey _key;
  bool _disposed = false;

  /// Возвращает PASERK `k4.local` строку.
  String toPaserk() {
    _ensureActive();
    return _key.toString();
  }

  /// Возвращает PASERK-идентификатор (k4.lid).
  String get identifier {
    _ensureActive();
    return K4Lid.fromKey(_key).toString();
  }

  /// Упаковывает ключ в `k4.local-pw`.
  Future<String> toPasswordPaserk({
    required String password,
    int memoryCost = K4LocalPw.defaultMemoryCost,
    int timeCost = K4LocalPw.defaultTimeCost,
    int parallelism = K4LocalPw.defaultParallelism,
  }) async {
    _ensureActive();
    final wrapped = await K4LocalPw.wrap(
      _key,
      password,
      memoryCost: memoryCost,
      timeCost: timeCost,
      parallelism: parallelism,
    );
    return wrapped.toString();
  }

  /// Восстанавливает ключ из `k4.local-pw` строки.
  static Future<PaserkSymmetricKey> fromPasswordPaserk({
    required String paserk,
    required String password,
  }) async {
    final key = await K4LocalPw.unwrap(paserk, password);
    return PaserkSymmetricKey._(key);
  }

  /// Упаковывает ключ в `k4.local-wrap.pie`, используя другой симметричный ключ.
  String toWrappedPaserk({required PaserkSymmetricKey wrappingKey}) {
    _ensureActive();
    wrappingKey._ensureActive();
    final wrapped = K4LocalWrap.wrap(_key, wrappingKey._key);
    return wrapped.toString();
  }

  /// Распаковывает `k4.local-wrap.pie` строку, используя заданный ключ.
  static PaserkSymmetricKey fromWrappedPaserk({
    required String paserk,
    required PaserkSymmetricKey wrappingKey,
  }) {
    final key = K4LocalWrap.unwrap(paserk, wrappingKey._key);
    return PaserkSymmetricKey._(key);
  }

  /// Запечатывает ключ в `k4.seal` для владельца публичного ключа.
  Future<String> toSealedPaserk({required PaserkPublicKey publicKey}) async {
    _ensureActive();
    publicKey._ensureValid();
    final wrapped = await K4Seal.seal(
      _key,
      publicKey._key,
    );
    return wrapped.toString();
  }

  /// Распаковывает `k4.seal` с помощью пары ключей получателя.
  static Future<PaserkSymmetricKey> fromSealedPaserk({
    required String paserk,
    required PaserkKeyPair keyPair,
  }) async {
    keyPair._ensureActive();
    final key = await K4Seal.unseal(paserk, keyPair._secret);
    return PaserkSymmetricKey._(key);
  }

  /// Обнуляет байты ключа в памяти. После вызова использовать объект нельзя.
  void dispose() {
    if (_disposed) return;
    _zero(_key.rawBytes);
    _disposed = true;
  }

  /// Выполняет действие с временным SecretKey и, опционально, диспоузит ключ.
  Future<T> withSecretKey<T>(
    Future<T> Function(SecretKey key) action, {
    bool disposeAfter = false,
  }) async {
    try {
      return await _useSecretKey(action);
    } finally {
      if (disposeAfter) {
        dispose();
      }
    }
  }

  Future<T> _useSecretKey<T>(Future<T> Function(SecretKey key) action) async {
    _ensureActive();
    final copy = Uint8List.fromList(_key.rawBytes);
    final secret = SecretKey(copy);
    try {
      return await action(secret);
    } finally {
      _zero(copy);
    }
  }

  Future<SecretKey> _asSecretKey() async {
    _ensureActive();
    return SecretKey(_key.rawBytes);
  }

  void _ensureActive() {
    if (_disposed) {
      throw StateError('The symmetric key has been disposed');
    }
  }
}
