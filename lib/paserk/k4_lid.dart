import 'dart:convert';
import 'dart:typed_data';

import '../blake2/_index.dart' as blake2lib;
import '../utils/base64_ext.dart';
import 'k4_local.dart';
import 'paserk_key.dart';

class K4Lid extends PaserkKey {
  static const int hashLength = 33; // BLAKE2b-264 = 33 bytes
  static const _prefix = 'k4.lid.';

  K4Lid(Uint8List bytes) : super(bytes, PaserkKey.k4LidPrefix) {
    if (bytes.length != hashLength) {
      throw ArgumentError('K4Lid must be exactly $hashLength bytes');
    }
  }

  static K4Lid fromKey(K4LocalKey key) {
    final paserk = key.toString(); // Получаем полный PASERK ключа
    final input =
        Uint8List.fromList(utf8.encode(_prefix) + utf8.encode(paserk));

    // Используем BLAKE2b-264 как указано в спецификации
    final blake2b = blake2lib.Blake2b(
      digestSize: hashLength, // 33 bytes для BLAKE2b-264
    );

    return K4Lid(blake2b.process(input));
  }

  static K4Lid fromString(String encoded) {
    if (!encoded.startsWith(PaserkKey.k4LidPrefix)) {
      throw ArgumentError('Invalid k4.lid format');
    }

    final decoded =
        SafeBase64.decode(encoded.substring(PaserkKey.k4LidPrefix.length));
    if (decoded.length != hashLength) {
      throw ArgumentError('Decoded k4.lid must be exactly $hashLength bytes');
    }
    return K4Lid(Uint8List.fromList(decoded));
  }

  @override
  String toString() {
    return PaserkKey.k4LidPrefix + SafeBase64.encode(rawBytes);
  }

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! K4Lid) return false;

    // Используем константное по времени сравнение
    if (rawBytes.length != other.rawBytes.length) return false;
    var result = 0;
    for (var i = 0; i < rawBytes.length; i++) {
      result |= rawBytes[i] ^ other.rawBytes[i];
    }
    return result == 0;
  }

  @override
  int get hashCode => Object.hash(
        PaserkKey.k4LidPrefix,
        Object.hashAll(rawBytes),
      );
}
