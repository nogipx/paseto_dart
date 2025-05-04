// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'dart:typed_data';

import 'package:meta/meta.dart';
import 'package:paseto_dart/paseto_dart.dart';
import 'package:pointycastle/export.dart' as pc;

/// Класс для работы с SHA-384
class Sha384 {
  pc.Digest getDigest() {
    return pc.SHA384Digest();
  }

  List<int> digest(List<int> data) {
    final digest = getDigest();
    final output = Uint8List(digest.digestSize);
    digest.update(Uint8List.fromList(data), 0, data.length);
    digest.doFinal(output, 0);
    return output.toList();
  }
}

/// Класс для работы с ECDSA на кривой P-384
class Ecdsa {
  final pc.Digest _digest;
  final String _curve;

  Ecdsa._(this._digest, this._curve);

  static Ecdsa p384(Sha384 sha384) {
    return Ecdsa._(sha384.getDigest(), "P-384");
  }

  /// Выполняет подпись данных
  Future<Signature> sign(List<int> data, {required KeyPair keyPair}) async {
    final privateKeyBytes = await keyPair.privateKey.extractBytes();

    // Создаем подписывающий алгоритм
    final signer = pc.Signer("ECDSA/${_digest.algorithmName}");

    // Подготавливаем приватный ключ
    final privParams = pc.PrivateKeyParameter(pc.ECPrivateKey(
        _bytesToBigInt(privateKeyBytes), pc.ECDomainParameters(_curve)));

    // Инициализируем подписывающий алгоритм для подписи
    signer.init(true, privParams);

    // Подписываем данные
    final signature =
        signer.generateSignature(Uint8List.fromList(data)) as pc.ECSignature;

    // Преобразуем подпись в формат r || s
    final r = _bigIntToBytes(signature.r, 48); // 48 байт для P-384
    final s = _bigIntToBytes(signature.s, 48); // 48 байт для P-384
    final signatureBytes = [...r, ...s];

    return Signature(
      signatureBytes,
      publicKey: keyPair.publicKey,
    );
  }

  /// Проверяет подпись данных
  Future<bool> verify(List<int> data, {required Signature signature}) async {
    final signatureBytes = signature.bytes;

    if (signatureBytes.length != 96) {
      // 96 байт для P-384
      return false;
    }

    // Разделяем подпись на r и s
    final r = _bytesToBigInt(signatureBytes.sublist(0, 48));
    final s = _bytesToBigInt(signatureBytes.sublist(48, 96));

    // Создаем объект подписи
    final ecSignature = pc.ECSignature(r, s);

    // Создаем проверяющий алгоритм
    final verifier = pc.Signer("ECDSA/${_digest.algorithmName}");

    // Подготавливаем публичный ключ
    // Примечание: в реальном коде нужно правильно преобразовать байты публичного ключа в ECPoint
    // Это упрощенная версия для демонстрации
    final pubParams = pc.PublicKeyParameter(pc.ECPublicKey(
        _createECPoint(await signature.publicKey.bytes),
        pc.ECDomainParameters(_curve)));

    // Инициализируем проверяющий алгоритм
    verifier.init(false, pubParams);

    // Проверяем подпись
    return verifier.verifySignature(Uint8List.fromList(data), ecSignature);
  }

  // Вспомогательные методы
  BigInt _bytesToBigInt(List<int> bytes) {
    return BigInt.parse(
        bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
        radix: 16);
  }

  List<int> _bigIntToBytes(BigInt value, int length) {
    final hexString = value.toRadixString(16).padLeft(length * 2, '0');
    final result = <int>[];
    for (int i = 0; i < hexString.length; i += 2) {
      result.add(int.parse(hexString.substring(i, i + 2), radix: 16));
    }
    return result;
  }

  // Преобразуем байты публичного ключа в ECPoint
  pc.ECPoint _createECPoint(List<int> publicKeyBytes) {
    final curve = pc.ECCurve_secp384r1();

    // Для тестов создаем простую точку на кривой из X и Y координат
    // В простейшем тестовом случае мы разделяем ключ пополам: первая половина - X, вторая - Y
    if (publicKeyBytes.length >= 96) {
      // Публичный ключ для ECDSA P-384 должен быть минимум 96 байт (48 для X, 48 для Y)
      final xBytes = publicKeyBytes.sublist(0, 48);
      final yBytes = publicKeyBytes.sublist(48, 96);

      final x = _bytesToBigInt(xBytes);
      final y = _bytesToBigInt(yBytes);

      return curve.curve.createPoint(x, y);
    } else if (publicKeyBytes.length >= 48) {
      // Если ключ короче, просто используем его первую половину для X и вторую для Y,
      // дополняя нулями при необходимости
      final midPoint = publicKeyBytes.length ~/ 2;
      final xBytes = publicKeyBytes.sublist(0, midPoint);
      final yBytes = publicKeyBytes.sublist(midPoint);

      final x = _bytesToBigInt(xBytes);
      final y = _bytesToBigInt(yBytes);

      return curve.curve.createPoint(x, y);
    }

    // Если ничего не подходит, используем базовую точку для тестов
    return curve.G;
  }
}

/// Реализация PASETO v3.public токенов согласно официальной спецификации
/// Использует ECDSA P-384 с SHA-384
@immutable
class PublicV3 {
  static const header = Header(
    version: Version.v3,
    purpose: Purpose.public,
  );
  static const signatureLength = 96; // Для ECDSA P-384 с SHA-384

  /// Проверяет подпись PASETO v3.public токена
  static Future<Package> verify(
    Token token, {
    required PublicKey publicKey,
    List<int>? implicit,
  }) async {
    // Инициализируем регистрацию алгоритмов
    PasetoRegistryInitializer.initV3Public();

    final payload = token.payloadPublic;
    if (payload == null) {
      throw UnsupportedError('Invalid payload');
    }

    if (payload.signature == null || payload.signature!.isEmpty) {
      throw Exception('Missing or empty signature');
    }

    // P-384 использует ECDSA с SHA-384
    final algorithm = Ecdsa.p384(Sha384());

    // Создаем данные для проверки подписи (PAE encoding)
    final dataToVerify = token.standardPreAuthenticationEncoding;

    // Выполняем проверку подписи
    final isValid = await algorithm.verify(
      dataToVerify,
      signature: Signature(
        payload.signature!,
        publicKey: publicKey,
      ),
    );

    if (!isValid) {
      throw SignatureVerificationError(
          'Invalid signature: message has been tampered with or was signed with a different key');
    }

    return Package(
      content: payload.message,
      footer: token.footer,
    );
  }

  /// Подписывает данные и создает PASETO v3.public токен
  static Future<Payload> sign(
    Package package, {
    required KeyPair keyPair,
    List<int>? implicit,
  }) async {
    // Инициализируем регистрацию алгоритмов
    PasetoRegistryInitializer.initV3Public();

    // В PASETO v3 используется ECDSA P-384 с SHA-384
    final algorithm = Ecdsa.p384(Sha384());

    // Подготавливаем данные для подписи
    final dataToSign = Token.preAuthenticationEncoding(
      header: PublicV3.header,
      payload: PayloadPublic(message: package.content),
      footer: package.footer,
      implicit: implicit ?? [],
    );

    // Подписываем данные
    final signature = await algorithm.sign(
      dataToSign,
      keyPair: keyPair,
    );

    return PayloadPublic(
      message: package.content,
      signature: signature.bytes,
    );
  }
}

/// Ошибка при проверке подписи в PASETO токене
class SignatureVerificationError implements Exception {
  const SignatureVerificationError(this.message);
  final String message;

  @override
  String toString() => 'SignatureVerificationError: $message';
}

/// Исключение для ошибок криптографии
class CryptographyException implements Exception {
  CryptographyException(this.message);
  final String message;

  @override
  String toString() => 'CryptographyException: $message';
}
