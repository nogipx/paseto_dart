// SPDX-FileCopyrightText: 2026 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: MIT

part of '_index.dart';

/// Соль для Argon2id/PBKW операций (используется с k4.local-pw).
final class PaserkSalt {
  PaserkSalt._(this.bytes);

  final Uint8List bytes;

  static const int defaultLength = K4LocalPw.saltLength;

  /// Генерирует криптографически стойкую соль.
  factory PaserkSalt.generate({int length = defaultLength}) {
    if (length < defaultLength) {
      throw ArgumentError('Salt length must be >= $defaultLength bytes');
    }
    final rand = math.Random.secure();
    final data = Uint8List(length);
    for (var i = 0; i < length; i++) {
      data[i] = rand.nextInt(256);
    }
    return PaserkSalt._(data);
  }

  /// Кодирует соль в Base64URL без паддинга.
  String toBase64() => SafeBase64.encode(bytes);

  @override
  String toString() => toBase64();

  factory PaserkSalt.fromBase64(String b64) =>
      PaserkSalt._(Uint8List.fromList(SafeBase64.decode(b64)));
}
