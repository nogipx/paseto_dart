import 'dart:typed_data';
import 'package:paseto_dart/common/crypto_types.dart';

extension SecretBoxNonce on SecretBox {
  SecretBox withNonce(Uint8List nonce) {
    return SecretBox(
      cipherText,
      nonce: nonce.toList(),
      mac: mac,
    );
  }
}
