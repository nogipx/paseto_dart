// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:meta/meta.dart';
import 'package:paseto_dart/common/crypto_types.dart';

/// Полная реализация Ed25519 для PASETO, использующая библиотеку ed25519_edwards.
///
/// Обеспечивает стандартную реализацию алгоритма Ed25519 согласно RFC 8032
/// для работы с токенами PASETO v2.public.
@immutable
class Ed25519 {
  const Ed25519();

  /// Размер подписи Ed25519 в байтах (64 байта / 512 бит)
  static const signatureSize = 64;

  /// Размер публичного ключа Ed25519 в байтах (32 байта / 256 бит)
  static const publicKeySize = 32;

  /// Размер приватного ключа Ed25519 в байтах (32 байта / 256 бит)
  static const privateKeySize = 32;

  /// Генерирует новую пару ключей Ed25519 используя криптографически
  /// стойкий генератор случайных чисел.
  Future<KeyPair> newKeyPair() async {
    // Используем библиотеку ed25519_edwards для генерации ключей
    // Внутренне она использует secure random из Dart
    final pair = ed.generateKey();

    // В библиотеке ed25519_edwards privateKey и publicKey являются типами Uint8List
    return KeyPair(
      privateKey: SecretKeyData(pair.privateKey.bytes),
      publicKey: PublicKeyData(pair.publicKey.bytes),
      keyType: KeyPairType.ed25519,
    );
  }

  /// Подписывает сообщение используя Ed25519
  Future<Signature> sign(
    List<int> message, {
    required KeyPair keyPair,
  }) async {
    final privateKeyBytes = await keyPair.privateKey.extractBytes();

    // В библиотеке ed25519_edwards приватный ключ должен быть 64 байта:
    // первые 32 байта - сам приватный ключ, вторые 32 байта - связанный публичный ключ
    List<int> fullPrivateKeyBytes;
    if (privateKeyBytes.length == 64) {
      // Ключ уже полный (64 байта)
      fullPrivateKeyBytes = privateKeyBytes;
    } else if (privateKeyBytes.length == privateKeySize) {
      // Ключ стандартного размера (32 байта) - нужно дополнить его публичным ключом
      final publicKeyBytes = await keyPair.publicKey.bytes;
      fullPrivateKeyBytes = [...privateKeyBytes, ...publicKeyBytes];
    } else {
      throw ArgumentError(
          'Invalid private key length: expected $privateKeySize bytes or 64 bytes');
    }

    // Преобразуем данные в нужный формат
    final messageBytes = Uint8List.fromList(message);

    // Создаем приватный ключ для ed25519_edwards с полной длиной
    final privateKey = ed.PrivateKey(Uint8List.fromList(fullPrivateKeyBytes));

    // Подписываем сообщение с помощью библиотеки ed25519_edwards
    final signature = ed.sign(privateKey, messageBytes);

    return Signature(
      signature.toList(),
      publicKey: keyPair.publicKey,
    );
  }

  /// Проверяет подпись Ed25519.
  Future<bool> verify(
    List<int> message, {
    required Signature signature,
  }) async {
    final publicKeyBytes = await signature.publicKey.bytes;

    if (publicKeyBytes.length != publicKeySize) {
      throw ArgumentError(
          'Invalid public key length: expected $publicKeySize bytes');
    }

    if (signature.bytes.length != signatureSize) {
      throw ArgumentError(
          'Invalid signature length: expected $signatureSize bytes');
    }

    // Преобразуем данные в нужный формат
    final messageBytes = Uint8List.fromList(message);
    final signatureBytes = Uint8List.fromList(signature.bytes);
    final publicKey = ed.PublicKey(Uint8List.fromList(publicKeyBytes));

    // Проверяем подпись
    try {
      return ed.verify(publicKey, messageBytes, signatureBytes);
    } catch (e) {
      // Если произошла ошибка при проверке, считаем подпись недействительной
      return false;
    }
  }
}

/// Представляет подпись Ed25519
@immutable
class Signature {
  const Signature(this.bytes, {required this.publicKey});

  /// Байты подписи
  final List<int> bytes;

  /// Публичный ключ для проверки
  final PublicKey publicKey;

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! Signature) return false;

    if (bytes.length != other.bytes.length) return false;

    for (var i = 0; i < bytes.length; i++) {
      if (bytes[i] != other.bytes[i]) return false;
    }

    return true;
  }

  @override
  int get hashCode => Object.hashAll(bytes);
}
