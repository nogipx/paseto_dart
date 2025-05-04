// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'dart:typed_data';
import 'package:pointycastle/export.dart';
// ignore: implementation_imports
import 'package:pointycastle/src/registry/registry.dart';

/// Инициализирует регистр алгоритмов PointyCastle для нужд библиотеки
class PasetoRegistryInitializer {
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
    // Базовые алгоритмы для ChaCha20-Poly1305
    registry.register(StaticFactoryConfig(
        StreamCipher, 'ChaCha7539', () => ChaCha7539Engine()));
    registry.register(StaticFactoryConfig(Mac, 'POLY1305', () => Poly1305()));
  }

  // ECDSA+P384+SHA384 для v3.public
  static void initV3Public() {
    registry
        .register(StaticFactoryConfig(Digest, 'SHA-384', () => SHA384Digest()));
    registry.register(StaticFactoryConfig(
        Signer, 'ECDSA/SHA-384', () => ECDSASigner(SHA384Digest())));

    // Регистрируем FortunaRandom для ECDSA
    final secureRandom = FortunaRandom();
    secureRandom
        .seed(KeyParameter(Uint8List.fromList(List.generate(32, (i) => i))));
    registry
        .register(StaticFactoryConfig(SecureRandom, '', () => secureRandom));

    // Регистрируем параметры кривой P-384
    final ecParams = ECCurve_secp384r1();
    registry.register(
        StaticFactoryConfig(ECDomainParameters, 'P-384', () => ecParams));
  }

  // Ed25519 для v4.public
  static void initV4Public() {
    // Только регистрируем FortunaRandom, т.к. используется отдельная реализация Ed25519
    final secureRandom = FortunaRandom();
    secureRandom
        .seed(KeyParameter(Uint8List.fromList(List.generate(32, (i) => i))));
    registry
        .register(StaticFactoryConfig(SecureRandom, '', () => secureRandom));
  }
}
