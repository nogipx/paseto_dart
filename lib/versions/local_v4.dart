// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'dart:convert';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:meta/meta.dart';
import 'package:paseto_dart/models/crypto.dart';
import 'package:paseto_dart/models/header.dart';
import 'package:paseto_dart/models/package.dart';
import 'package:paseto_dart/models/payload.dart';
import 'package:paseto_dart/models/purpose.dart';
import 'package:paseto_dart/utils/registry_init.dart';
import 'package:paseto_dart/models/token.dart';
import 'package:paseto_dart/models/version.dart';
import 'package:paseto_dart/crypto/_index.dart';
import 'package:pointycastle/export.dart' as pc;

/// Класс для хранения ключей шифрования и аутентификации
@immutable
class _KeySet {
  const _KeySet({
    required this.encKey,
    required this.authKey,
    required this.nonce2,
  });

  final List<int> encKey;
  final List<int> authKey;
  final List<int> nonce2;
}

/// Реализация PASETO v4.local для шифрования и расшифрования токенов
@immutable
class LocalV4 {
  /// Константы для v4.local
  static const nonceLength = 32; // XChaCha20 nonce размер в байтах
  static const macLength = 32; // BLAKE2b-256 MAC размер в байтах
  static const encKeyLength =
      32; // XChaCha20-Poly1305 ключ шифрования размер в байтах
  static const encKeyInfo =
      'paseto-encryption-key'; // Информация для ключа шифрования
  static const authKeyInfo =
      'paseto-auth-key-for-aead'; // Информация для ключа аутентификации

  /// Заголовок для v4.local
  static const header = Header(
    version: Version.v4,
    purpose: Purpose.local,
  );

  /// Выводит ключи шифрования и аутентификации с использованием BLAKE2b-HKDF
  static _KeySet _deriveKeys(
    List<int> key,
    List<int> nonce, {
    List<int> implicit = const [],
  }) {
    // Проверяем длину ключа для BLAKE2b
    if (key.length != 32) {
      throw ArgumentError('Key must be 32 bytes for v4.local');
    }

    // Создаем keyed BLAKE2b для вывода ключа шифрования и nonce2
    // Общий размер вывода: 56 байт (32 байта для ключа + 24 байта для nonce2)
    final encBlake = pc.Blake2bDigest(
        digestSize: encKeyLength + 24, key: Uint8List.fromList(key));

    // Сообщение для encBlake: domain separation constant || nonce
    final encMsg = Uint8List.fromList([
      ...utf8.encode(encKeyInfo),
      ...nonce,
    ]);

    encBlake.update(encMsg, 0, encMsg.length);

    final tmp = Uint8List(encKeyLength + 24);
    encBlake.doFinal(tmp, 0);

    // Разделяем tmp на ключ шифрования и nonce2
    final encKey = tmp.sublist(0, encKeyLength);
    final nonce2 = tmp.sublist(encKeyLength, encKeyLength + 24);

    // Создаем keyed BLAKE2b для ключа аутентификации (32 байта)
    final authBlake =
        pc.Blake2bDigest(digestSize: macLength, key: Uint8List.fromList(key));

    // Сообщение для authBlake: domain separation constant || nonce
    final authMsg = Uint8List.fromList([
      ...utf8.encode(authKeyInfo),
      ...nonce,
    ]);

    authBlake.update(authMsg, 0, authMsg.length);

    final authKey = Uint8List(macLength);
    authBlake.doFinal(authKey, 0);

    return _KeySet(
      encKey: encKey.toList(),
      authKey: authKey.toList(),
      nonce2: nonce2.toList(),
    );
  }

  /// Расшифровывает PASETO v4.local токен и проверяет его целостность
  static Future<Package> decrypt(
    Token token, {
    required SecretKey secretKey,
    List<int>? implicit,
  }) async {
    // Инициализируем регистр PointyCastle для v4.local
    PasetoRegistryInitializer.initV4Local();

    // Проверка версии и purpose токена
    if (token.header.version != Version.v4 ||
        token.header.purpose != Purpose.local) {
      throw FormatException('Token format is incorrect: not a v4.local token');
    }

    final payload = token.payloadLocal;
    if (payload == null) throw UnsupportedError('Invalid payload type.');

    // Получаем nonce и ciphertext из payload
    final nonce = payload.nonce!.bytes;
    final secretBoxData = payload.secretBox!.cipherText;

    // Получаем ключевой материал
    final secretKeyBytes = await secretKey.extractBytes();
    if (secretKeyBytes.length < 32) {
      throw FormatException('Secret key must be at least 32 bytes');
    }

    // Используем установленные implicit или пустой массив
    final implicitBytes = implicit ?? [];

    // Выводим ключи для расшифровки и аутентификации
    final derivedKeys =
        _deriveKeys(secretKeyBytes, nonce, implicit: implicitBytes);
    final encryptionKey = derivedKeys.encKey;
    final authKey = derivedKeys.authKey;
    final nonce2 = derivedKeys.nonce2;

    // Разделяем секретный блок на зашифрованный текст и MAC
    final macBytes = secretBoxData.sublist(secretBoxData.length - macLength);
    final cipherText =
        secretBoxData.sublist(0, secretBoxData.length - macLength);

    // Вычисляем ожидаемый MAC для проверки аутентичности
    final footer = token.footer ?? [];
    final computedMac = _computeBlake2bMac(
      authKey,
      nonce,
      cipherText,
      footer,
      implicit: implicitBytes,
    );

    print('Provided MAC: ${hex.encode(macBytes)}');
    print('Computed MAC: ${hex.encode(computedMac)}');
    print('Nonce: ${hex.encode(nonce)}');
    print('Auth Key: ${hex.encode(authKey)}');
    print('Enc Key: ${hex.encode(encryptionKey)}');
    if (implicitBytes.isNotEmpty) {
      print('Implicit Assertion: ${utf8.decode(implicitBytes)}');
    }

    // Проверяем совпадение MAC
    if (!_constantTimeEquals(macBytes, computedMac)) {
      throw SecretBoxAuthenticationError(
          'Authentication failed: MAC verification failed');
    }

    // Расшифровываем данные с использованием XChaCha20
    const xchacha = XChaCha20Direct();
    final clearText = xchacha.decrypt(
      cipherText,
      key: encryptionKey,
      nonce: nonce2,
    );

    // Возвращаем расшифрованный контент и footer
    return Package(content: clearText, footer: footer);
  }

  /// Шифрует данные и создает PASETO v4.local токен
  static Future<Payload> encrypt(
    Package package, {
    required SecretKey secretKey,
    List<int>? implicit,
  }) async {
    // Инициализируем регистр PointyCastle для v4.local
    PasetoRegistryInitializer.initV4Local();

    // Получаем ключевой материал
    final secretKeyBytes = await secretKey.extractBytes();
    if (secretKeyBytes.length < 32) {
      throw FormatException('Secret key must be at least 32 bytes');
    }

    // Генерируем случайный nonce длиной 32 байта для v4
    final random = math.Random.secure();
    final nonceBytes = Uint8List(nonceLength);
    for (var i = 0; i < nonceLength; i++) {
      nonceBytes[i] = random.nextInt(256);
    }
    final nonce = nonceBytes.toList();

    // Используем установленные implicit или пустой массив
    final implicitBytes = implicit ?? [];

    // Выводим ключи для шифрования и аутентификации
    final derivedKeys =
        _deriveKeys(secretKeyBytes, nonce, implicit: implicitBytes);
    final encryptionKey = derivedKeys.encKey;
    final authKey = derivedKeys.authKey;
    final nonce2 = derivedKeys.nonce2;

    // Шифруем с использованием XChaCha20
    const xchacha = XChaCha20Direct();
    final cipherText = xchacha.encrypt(
      Uint8List.fromList(package.content),
      key: encryptionKey,
      nonce: nonce2,
    );

    // Вычисляем MAC для аутентификации
    final footer = package.footer ?? [];
    final mac = _computeBlake2bMac(
      authKey,
      nonce,
      cipherText,
      footer,
      implicit: implicitBytes,
    );

    // Объединяем зашифрованный текст и MAC
    final combinedCipherText = [...cipherText, ...mac];

    // Возвращаем PASETO v4.local payload
    final nonceWrapper = MacWrapper(nonce);
    return PayloadLocal(
      nonce: nonceWrapper,
      secretBox: SecretBox(
        combinedCipherText,
        nonce: nonce,
        mac: MacWrapper(mac),
      ),
    );
  }

  /// Сравнивает два массива байтов в постоянном времени для защиты от атак по времени
  static bool _constantTimeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    int result = 0;
    for (int i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result == 0;
  }

  /// Вычисляет MAC на основе BLAKE2b для v4.local
  static List<int> _computeBlake2bMac(
    List<int> authKey,
    List<int> nonce,
    List<int> cipherText,
    List<int> footer, {
    List<int> implicit = const [],
  }) {
    // Создаем предварительно аутентифицированное кодирование (PAE)
    final preAuth = _preAuthenticationEncoding([
      Uint8List.fromList(utf8.encode("v4.local.")),
      Uint8List.fromList(nonce),
      Uint8List.fromList(cipherText),
      Uint8List.fromList(footer),
      Uint8List.fromList(implicit),
    ]);

    // Создаем BLAKE2b-MAC с ключом authKey
    final mac = pc.Blake2bDigest(
        digestSize: macLength, key: Uint8List.fromList(authKey));

    // Добавляем предварительно аутентифицированное кодирование в MAC
    mac.update(Uint8List.fromList(preAuth), 0, preAuth.length);

    // Вычисляем MAC
    final result = Uint8List(macLength);
    mac.doFinal(result, 0);
    return result.toList();
  }

  /// Создает PAE (Pre-Authentication Encoding) из компонентов
  static List<int> _preAuthenticationEncoding(List<Uint8List> pieces) {
    final count = pieces.length;
    final countBytes = Uint8List(8);
    final view = ByteData.view(countBytes.buffer);
    view.setUint64(0, count, Endian.little);

    // Создаем буфер с размером для всех компонентов
    int totalLength = 8; // Сначала 8 байтов для количества компонентов
    for (final piece in pieces) {
      totalLength += 8; // 8 байтов для длины компонента
      totalLength += piece.length; // размер самого компонента
    }

    final output = Uint8List(totalLength);
    final buffer = ByteData.view(output.buffer);

    // Записываем количество компонентов
    buffer.setUint64(0, count, Endian.little);
    int offset = 8;

    // Записываем каждый компонент с его длиной
    for (final piece in pieces) {
      // Записываем длину компонента
      buffer.setUint64(offset, piece.length, Endian.little);
      offset += 8;

      // Записываем сам компонент
      for (int i = 0; i < piece.length; i++) {
        output[offset + i] = piece[i];
      }
      offset += piece.length;
    }

    return output;
  }
}

/// Обертка для Mac чтобы избежать конфликтов имен с PointyCastle
@immutable
class MacWrapper implements Mac {
  const MacWrapper(this._bytes);

  final List<int> _bytes;

  @override
  List<int> get bytes => _bytes;

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! Mac) return false;

    if (bytes.length != other.bytes.length) return false;

    for (var i = 0; i < bytes.length; i++) {
      if (bytes[i] != other.bytes[i]) return false;
    }

    return true;
  }

  @override
  int get hashCode => Object.hashAll(bytes);
}

/// Исключение возникающее при неправильном MAC
class SecretBoxAuthenticationError implements Exception {
  const SecretBoxAuthenticationError(this.message);
  final String message;

  @override
  String toString() => 'SecretBoxAuthenticationError: $message';
}
