// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'dart:typed_data';
import 'package:paseto_dart/blake2/ufixnum.dart';
import 'package:paseto_dart/chacha20/chacha20_pointycastle.dart';

/// Константа расширения ключа для ChaCha20.
/// Это ASCII значения строки "expand 32-byte k".
const _sigma = [
  0x65,
  0x78,
  0x70,
  0x61,
  0x6e,
  0x64,
  0x20,
  0x33,
  0x32,
  0x2d,
  0x62,
  0x79,
  0x74,
  0x65,
  0x20,
  0x6b
];

/// Реализация XChaCha20 на основе ChaCha20 из PointyCastle,
/// строго в соответствии со спецификацией PASETO
class XChaCha20 extends ChaCha20 {
  XChaCha20() : super();

  /// Initialize XChaCha20 with a 24-byte nonce
  @override
  void init(bool forEncryption, ParametersWithIV<KeyParameter> params) {
    var iv = params.iv;
    if (iv.length != 24) {
      throw ArgumentError('XChaCha20 requires exactly 24 bytes of IV');
    }

    // Извлекаем первые 16 байт nonce для HChaCha20
    var hNonce = iv.sublist(0, 16);

    // Получаем новый ключ через HChaCha20
    var subKey = Uint8List(32);
    _hchacha20(params.parameters!.key, hNonce, subKey);

    // Последние 8 байт nonce используются как обычный nonce для ChaCha20
    // Counter (4 байта 0) идет ПЕРЕД nonce согласно спецификации ChaCha20
    var shortened = Uint8List(12); // ChaCha20 expects a 12-byte nonce
    shortened.setAll(0, [0, 0, 0, 0]); // Counter в начале (4 байта 0)
    shortened.setAll(4, iv.sublist(16)); // Последние 8 байт XChaCha20 nonce

    // Инициализируем базовый ChaCha20 с новым ключом и укороченным nonce
    super
        .init(forEncryption, ParametersWithIV(KeyParameter(subKey), shortened));
  }

  /// Реализация HChaCha20 в точном соответствии со спецификацией
  /// https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-03
  void _hchacha20(Uint8List key, List<int> nonce, Uint8List out) {
    // Преобразуем константные списки в Uint8List для избежания ошибки buffer
    // _ImmutableList не имеет свойства buffer, необходимого для unpack32
    final nonceBytes = Uint8List.fromList(nonce);
    final sigmaBytes = Uint8List.fromList(_sigma);
    final keyBytes = Uint8List.fromList(key);

    // Инициализируем начальное состояние ChaCha20
    var state = List<int>.filled(16, 0, growable: false);

    // Constants (sigma)
    state[0] = unpack32(sigmaBytes, 0, Endian.little);
    state[1] = unpack32(sigmaBytes, 4, Endian.little);
    state[2] = unpack32(sigmaBytes, 8, Endian.little);
    state[3] = unpack32(sigmaBytes, 12, Endian.little);

    // Key
    state[4] = unpack32(keyBytes, 0, Endian.little);
    state[5] = unpack32(keyBytes, 4, Endian.little);
    state[6] = unpack32(keyBytes, 8, Endian.little);
    state[7] = unpack32(keyBytes, 12, Endian.little);
    state[8] = unpack32(keyBytes, 16, Endian.little);
    state[9] = unpack32(keyBytes, 20, Endian.little);
    state[10] = unpack32(keyBytes, 24, Endian.little);
    state[11] = unpack32(keyBytes, 28, Endian.little);

    // Nonce (16 bytes)
    state[12] = unpack32(nonceBytes, 0, Endian.little);
    state[13] = unpack32(nonceBytes, 4, Endian.little);
    state[14] = unpack32(nonceBytes, 8, Endian.little);
    state[15] = unpack32(nonceBytes, 12, Endian.little);

    // Выполняем 20 раундов ChaCha20 без финального добавления к входному состоянию
    var x = List<int>.filled(16, 0, growable: false);
    // Копируем исходное состояние в x
    for (int i = 0; i < 16; i++) {
      x[i] = state[i];
    }

    // Выполняем 20 раундов ChaCha20
    _chachaRounds(x, 20);

    // Копируем первые 4 слова и последние 4 слова в выходной буфер
    // в соответствии со спецификацией HChaCha20
    pack32(x[0], out, 0, Endian.little);
    pack32(x[1], out, 4, Endian.little);
    pack32(x[2], out, 8, Endian.little);
    pack32(x[3], out, 12, Endian.little);
    pack32(x[12], out, 16, Endian.little);
    pack32(x[13], out, 20, Endian.little);
    pack32(x[14], out, 24, Endian.little);
    pack32(x[15], out, 28, Endian.little);
  }

  /// Реализация раундов ChaCha20 без финального добавления
  void _chachaRounds(List<int> x, int rounds) {
    var x00 = x[0];
    var x01 = x[1];
    var x02 = x[2];
    var x03 = x[3];
    var x04 = x[4];
    var x05 = x[5];
    var x06 = x[6];
    var x07 = x[7];
    var x08 = x[8];
    var x09 = x[9];
    var x10 = x[10];
    var x11 = x[11];
    var x12 = x[12];
    var x13 = x[13];
    var x14 = x[14];
    var x15 = x[15];

    for (var i = rounds; i > 0; i -= 2) {
      // Column round
      x00 += x04;
      x12 = crotl32(x12 ^ x00, 16);
      x08 += x12;
      x04 = crotl32(x04 ^ x08, 12);
      x00 += x04;
      x12 = crotl32(x12 ^ x00, 8);
      x08 += x12;
      x04 = crotl32(x04 ^ x08, 7);

      x01 += x05;
      x13 = crotl32(x13 ^ x01, 16);
      x09 += x13;
      x05 = crotl32(x05 ^ x09, 12);
      x01 += x05;
      x13 = crotl32(x13 ^ x01, 8);
      x09 += x13;
      x05 = crotl32(x05 ^ x09, 7);

      x02 += x06;
      x14 = crotl32(x14 ^ x02, 16);
      x10 += x14;
      x06 = crotl32(x06 ^ x10, 12);
      x02 += x06;
      x14 = crotl32(x14 ^ x02, 8);
      x10 += x14;
      x06 = crotl32(x06 ^ x10, 7);

      x03 += x07;
      x15 = crotl32(x15 ^ x03, 16);
      x11 += x15;
      x07 = crotl32(x07 ^ x11, 12);
      x03 += x07;
      x15 = crotl32(x15 ^ x03, 8);
      x11 += x15;
      x07 = crotl32(x07 ^ x11, 7);

      // Diagonal round
      x00 += x05;
      x15 = crotl32(x15 ^ x00, 16);
      x10 += x15;
      x05 = crotl32(x05 ^ x10, 12);
      x00 += x05;
      x15 = crotl32(x15 ^ x00, 8);
      x10 += x15;
      x05 = crotl32(x05 ^ x10, 7);

      x01 += x06;
      x12 = crotl32(x12 ^ x01, 16);
      x11 += x12;
      x06 = crotl32(x06 ^ x11, 12);
      x01 += x06;
      x12 = crotl32(x12 ^ x01, 8);
      x11 += x12;
      x06 = crotl32(x06 ^ x11, 7);

      x02 += x07;
      x13 = crotl32(x13 ^ x02, 16);
      x08 += x13;
      x07 = crotl32(x07 ^ x08, 12);
      x02 += x07;
      x13 = crotl32(x13 ^ x02, 8);
      x08 += x13;
      x07 = crotl32(x07 ^ x08, 7);

      x03 += x04;
      x14 = crotl32(x14 ^ x03, 16);
      x09 += x14;
      x04 = crotl32(x04 ^ x09, 12);
      x03 += x04;
      x14 = crotl32(x14 ^ x03, 8);
      x09 += x14;
      x04 = crotl32(x04 ^ x09, 7);
    }

    // Записываем результат обратно в массив
    x[0] = x00;
    x[1] = x01;
    x[2] = x02;
    x[3] = x03;
    x[4] = x04;
    x[5] = x05;
    x[6] = x06;
    x[7] = x07;
    x[8] = x08;
    x[9] = x09;
    x[10] = x10;
    x[11] = x11;
    x[12] = x12;
    x[13] = x13;
    x[14] = x14;
    x[15] = x15;
  }
}
