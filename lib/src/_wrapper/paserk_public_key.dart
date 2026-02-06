// SPDX-FileCopyrightText: 2026 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: MIT

part of '_index.dart';

/// Непривилегированный обёртка для публичного ключа Ed25519 (k4.public).
final class PaserkPublicKey {
  PaserkPublicKey._(this._key);

  final K4PublicKey _key;

  /// Создаёт из PASERK `k4.public` строки.
  factory PaserkPublicKey.fromPaserk(String paserk) =>
      PaserkPublicKey._(K4PublicKey.fromString(paserk));

  /// Создаёт из сырых 32 байт публичного ключа.
  factory PaserkPublicKey.fromBytes(List<int> bytes) =>
      PaserkPublicKey._(K4PublicKey(Uint8List.fromList(bytes)));

  /// Возвращает PASERK строку `k4.public`.
  String toPaserk() => _key.toString();

  /// Возвращает PASERK идентификатор (k4.pid).
  String get identifier => K4Pid.fromKey(_key).toString();

  /// Преобразует в `SimplePublicKey` для низкоуровневых API.
  Future<SimplePublicKey> _asSimple() async {
    _ensureValid();
    return SimplePublicKey(_key.rawBytes, type: KeyPairType.ed25519);
  }

  void _ensureValid() {
    if (_key.rawBytes.length != K4PublicKey.keyLength) {
      throw ArgumentError('Public key must be 32 bytes');
    }
  }
}
