// SPDX-FileCopyrightText: 2026 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: MIT

part of '_index.dart';

/// Generates cryptographically secure NanoIDs (ported from licensify).
final class NanoId {
  NanoId._();

  static const int defaultSize = 21;
  static const String defaultAlphabet =
      '_-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

  static final math.Random _random = math.Random.secure();

  static String generate({
    int size = defaultSize,
    String alphabet = defaultAlphabet,
  }) {
    if (size <= 0) {
      throw ArgumentError.value(size, 'size', 'must be positive');
    }
    if (alphabet.isEmpty) {
      throw ArgumentError.value(alphabet, 'alphabet', 'must not be empty');
    }
    if (alphabet.length > 255) {
      throw ArgumentError.value(
        alphabet,
        'alphabet',
        'must not contain more than 255 symbols',
      );
    }

    if (alphabet.length == 1) {
      return alphabet * size;
    }

    final length = alphabet.length;
    final mask = (2 << ((math.log(length - 1) / math.ln2).floor())) - 1;
    final step = ((1.6 * mask * size) / length).ceil();

    final buffer = StringBuffer();
    while (true) {
      final bytes = Uint8List(step);
      for (var i = 0; i < step; i++) {
        bytes[i] = _random.nextInt(256);
      }
      for (var i = 0; i < step; i++) {
        final index = bytes[i] & mask;
        if (index < length) {
          buffer.write(alphabet[index]);
          if (buffer.length == size) {
            return buffer.toString();
          }
        }
      }
    }
  }
}
