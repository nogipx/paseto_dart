// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'dart:typed_data';
import 'package:pointycastle/export.dart';
// ignore: implementation_imports
import 'package:pointycastle/src/registry/registry.dart';

/// Инициализирует регистр алгоритмов PointyCastle для нужд библиотеки
class PasetoRegistryInitializer {
  // ChaCha20-Poly1305 для v2.local
  static void initV2Local() {
    registry.register(StaticFactoryConfig(
        StreamCipher, 'ChaCha7539', () => ChaCha7539Engine()));
    registry.register(StaticFactoryConfig(Mac, 'POLY1305', () => Poly1305()));
  }

  // AES-CTR + HMAC для v3.local
  static void initV3Local() {
    registry
        .register(StaticFactoryConfig(BlockCipher, 'AES', () => AESEngine()));
    registry.register(StaticFactoryConfig(
        StreamCipher, 'CTR/AES', () => CTRStreamCipher(AESEngine())));
    registry
        .register(StaticFactoryConfig(Digest, 'SHA-384', () => SHA384Digest()));
    registry.register(StaticFactoryConfig(
        Mac, 'HMAC/SHA384', () => HMac(SHA384Digest(), 128)));
    registry.register(StaticFactoryConfig(
        KeyDerivator, 'HKDF/SHA-384', () => HKDFKeyDerivator(SHA384Digest())));
  }

  // XChaCha20-Poly1305 для v4.local
  static void initV4Local() {
    registry.register(StaticFactoryConfig(
        StreamCipher, 'ChaCha7539', () => ChaCha7539Engine()));
    registry.register(StaticFactoryConfig(Mac, 'POLY1305', () => Poly1305()));

    // Регистрируем XChaCha20 в виде ChaCha20 с измененным nonce
    registry.register(StaticFactoryConfig(
        StreamCipher, 'XChaCha20', () => ChaCha7539Engine()));

    // Добавляем алгоритмы для HKDF и SHA-512
    registry
        .register(StaticFactoryConfig(Digest, 'SHA-512', () => SHA512Digest()));
    registry.register(StaticFactoryConfig(
        KeyDerivator, 'HKDF/SHA-512', () => HKDFKeyDerivator(SHA512Digest())));

    // Регистрируем Blake2b как дайджест
    // Для использования в keyed mode он будет инициализирован отдельно с правильными параметрами
    registry.register(StaticFactoryConfig(
        Digest, 'BLAKE2B', () => Blake2bDigest(digestSize: 32)));

    // Регистрируем Blake2b/256 как Mac для v4.local
    registry.register(StaticFactoryConfig(
        Mac, 'BLAKE2b/256', () => HMac(Blake2bDigest(digestSize: 32), 64)));
  }

  // Ed25519 для v2.public
  static void initV2Public() {
    // Используем собственную реализацию Ed25519
  }

  // ECDSA+P384+SHA384 для v3.public
  static void initV3Public() {
    registry
        .register(StaticFactoryConfig(Digest, 'SHA-384', () => SHA384Digest()));
    registry.register(StaticFactoryConfig(
        Signer, 'ECDSA/SHA-384', () => ECDSASigner(SHA384Digest())));

    // Регистрируем FortunaRandom для ECDSA и инициализируем его
    final secureRandom = FortunaRandom();
    secureRandom
        .seed(KeyParameter(Uint8List.fromList(List.generate(32, (i) => i))));
    registry
        .register(StaticFactoryConfig(SecureRandom, '', () => secureRandom));

    // Чтобы избежать бесконечной рекурсии, создаем ECDomainParameters заранее
    // и регистрируем уже созданный экземпляр
    final ecParams = ECCurve_secp384r1();
    registry.register(
        StaticFactoryConfig(ECDomainParameters, 'P-384', () => ecParams));
  }

  // Ed25519 для v4.public
  static void initV4Public() {
    // Регистрируем FortunaRandom для Ed25519
    final secureRandom = FortunaRandom();
    secureRandom
        .seed(KeyParameter(Uint8List.fromList(List.generate(32, (i) => i))));
    registry
        .register(StaticFactoryConfig(SecureRandom, '', () => secureRandom));

    // Используем собственную реализацию Ed25519
  }
}
