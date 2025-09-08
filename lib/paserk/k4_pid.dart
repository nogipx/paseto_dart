import 'dart:convert';
import 'dart:typed_data';

import '../blake2/_index.dart' as blake2lib;
import '../utils/base64_ext.dart';
import 'k4_public.dart';
import 'paserk_key.dart';

class K4Pid extends PaserkKey {
  static const int hashLength = 33; // BLAKE2b-264 = 33 bytes
  static const _prefix = 'k4.pid.';

  K4Pid(Uint8List bytes) : super(bytes, PaserkKey.k4PidPrefix) {
    if (bytes.length != hashLength) {
      throw ArgumentError('K4Pid must be exactly $hashLength bytes');
    }
  }

  static K4Pid fromKey(K4PublicKey key) {
    final paserk = key.toString(); // Получаем полный PASERK ключа
    final input =
        Uint8List.fromList(utf8.encode(_prefix) + utf8.encode(paserk));

    // Используем BLAKE2b-264 как указано в спецификации
    final blake2b = blake2lib.Blake2b(
      digestSize: hashLength, // 33 bytes для BLAKE2b-264
    );

    return K4Pid(blake2b.process(input));
  }

  static K4Pid fromString(String encoded) {
    if (!encoded.startsWith(PaserkKey.k4PidPrefix)) {
      throw ArgumentError('Invalid k4.pid format');
    }

    final decoded =
        SafeBase64.decode(encoded.substring(PaserkKey.k4PidPrefix.length));
    if (decoded.length != hashLength) {
      throw ArgumentError('Decoded k4.pid must be exactly $hashLength bytes');
    }
    return K4Pid(Uint8List.fromList(decoded));
  }

  @override
  String toString() {
    return PaserkKey.k4PidPrefix + SafeBase64.encode(rawBytes);
  }

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! K4Pid) return false;

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
        PaserkKey.k4PidPrefix,
        Object.hashAll(rawBytes),
      );
}
