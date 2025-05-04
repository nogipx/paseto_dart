// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'dart:convert';
import 'dart:typed_data';

import 'package:equatable/equatable.dart';
import 'package:meta/meta.dart';
import 'package:paseto_dart/paseto_dart.dart';
import 'package:paseto_dart/versions/local_v4.dart' show MacWrapper;

@immutable
class Token extends Equatable {
  const Token({
    required this.header,
    required this.payload,
    required this.footer,
  });

  final Header header;
  final Payload payload;
  final List<int>? footer;

  PayloadLocal? get payloadLocal {
    return payload as PayloadLocal;
  }

  PayloadPublic? get payloadPublic {
    return payload as PayloadPublic;
  }

  String get toTokenString {
    var tokenString = header.toTokenString + payload.toTokenString;
    final footer = this.footer;
    if (footer != null && footer.isNotEmpty) {
      tokenString += '.${encodePasetoBase64(footer)}';
    }
    return tokenString;
  }

  Future<Message> decryptLocalMessage({
    required SecretKey secretKey,
    List<int>? implicit,
  }) async {
    if (header.purpose != Purpose.local) {
      throw UnsupportedError('Unable to decrypt non-local message');
    }
    return Message(
      header: header,
      package: await _decryptPackage(secretKey: secretKey, implicit: implicit),
      payload: payload,
    );
  }

  Future<Package> _decryptPackage({
    required SecretKey secretKey,
    List<int>? implicit,
  }) async {
    switch (header.version) {
      case Version.v2:
        return LocalV2.decrypt(
          this,
          secretKey: secretKey,
        );
      case Version.v3:
        return LocalV3.decrypt(
          this,
          secretKey: secretKey,
          implicit: implicit,
        );
      case Version.v4:
        return LocalV4.decrypt(
          this,
          secretKey: secretKey,
          implicit: implicit,
        );
    }
  }

  Future<Message> verifyPublicMessage({
    required PublicKey publicKey,
    List<int>? implicit,
  }) async {
    if (header.purpose != Purpose.public) {
      throw UnsupportedError('Unable to verify non-public message');
    }
    return Message(
      header: header,
      package: await _verifyPackage(publicKey: publicKey, implicit: implicit),
      payload: payload,
    );
  }

  Future<Package> _verifyPackage({
    required PublicKey publicKey,
    List<int>? implicit,
  }) async {
    switch (header.version) {
      case Version.v2:
        return PublicV2.verify(
          this,
          publicKey: publicKey,
        );
      case Version.v3:
        return PublicV3.verify(
          this,
          publicKey: publicKey,
          implicit: implicit,
        );
      case Version.v4:
        return PublicV4.verify(
          this,
          publicKey: publicKey,
          implicit: implicit,
        );
    }
  }

  static Future<Token> fromString(String string) async {
    final components = string.split('.');
    if (components.length < 3) {
      throw ArgumentError('Invalid token string', 'string');
    }

    // Первый компонент должен быть вида "v4" (версия)
    final versionStr = components.first;
    if (!versionStr.startsWith('v')) {
      throw FormatException(
          'Token version must start with "v", got: $versionStr');
    }

    // Второй компонент должен быть purpose (local/public)
    final purposeStr = components[1];

    // Проверяем, что версия и purpose корректны
    Version version;
    try {
      // Убираем префикс "v" из строки версии
      final versionNum = versionStr.substring(1);

      // Поддерживаем все версии: v2, v3, v4
      version = Version.values.byName('v$versionNum');
    } catch (e) {
      throw FormatException('Unsupported token version: $versionStr');
    }

    Purpose purpose;
    try {
      purpose = Purpose.values.byName(purposeStr);
    } catch (e) {
      throw FormatException('Unsupported token purpose: $purposeStr');
    }

    final header = Header(
      version: version,
      purpose: purpose,
    );

    return Token(
      header: header,
      payload: decodePayload(components[2], header: header),
      footer: components.length > 3 ? decodePasetoBase64(components[3]) : null,
    );
  }

  static Payload decodePayload(
    String string, {
    required Header header,
  }) {
    final bytes = decodePasetoBase64(string);

    // Используем общую логику декодирования в зависимости от версии и purpose
    switch (header.purpose) {
      case Purpose.local:
        return _decodeLocalPayload(bytes, header.version);
      case Purpose.public:
        return _decodePublicPayload(bytes, header.version);
    }
  }

  static Payload _decodeLocalPayload(List<int> bytes, Version version) {
    int nonceLength = 0;
    int macLength = 0;

    // Определяем длины nonce и MAC для версии
    switch (version) {
      case Version.v2:
        nonceLength = LocalV2.nonceLength;
        macLength = LocalV2.macLength;
        break;
      case Version.v3:
        nonceLength = LocalV3.nonceLength;
        macLength = LocalV3.macLength;
        break;
      case Version.v4:
        nonceLength = LocalV4.nonceLength;
        macLength = LocalV4.macLength;
        break;
    }

    // Проверяем минимальную длину payload
    if (bytes.length < nonceLength) {
      throw FormatException(
          'Invalid token payload length for ${version.name}.local: expected at least $nonceLength bytes, got ${bytes.length}');
    }

    // Извлекаем nonce
    final nonce = bytes.sublist(0, nonceLength);

    // Извлекаем шифротекст с MAC
    final cipherTextWithMac = bytes.sublist(nonceLength);

    // В v4 всегда должен быть достаточный размер для MAC
    if (cipherTextWithMac.length < macLength) {
      throw FormatException(
          'Invalid token ciphertext length for ${version.name}.local: expected at least $macLength bytes for MAC, got ${cipherTextWithMac.length}');
    }

    // Создаем payload
    return PayloadLocal(
      secretBox: SecretBox(
        cipherTextWithMac,
        nonce: nonce,
        mac: MacWrapper(
            cipherTextWithMac.sublist(cipherTextWithMac.length - macLength)),
      ),
      nonce: MacWrapper(nonce),
    );
  }

  static Payload _decodePublicPayload(List<int> bytes, Version version) {
    int signatureLength = 0;

    // Определяем длину подписи для версии
    switch (version) {
      case Version.v2:
        signatureLength = PublicV2.signatureLength;
        break;
      case Version.v3:
        signatureLength = PublicV3.signatureLength;
        break;
      case Version.v4:
        signatureLength = PublicV4.signatureLength;
        break;
    }

    // Проверяем минимальную длину payload
    if (bytes.length < signatureLength) {
      throw FormatException(
          'Invalid token payload length for ${version.name}.public: expected at least $signatureLength bytes, got ${bytes.length}');
    }

    // Извлекаем сообщение (оно идет в начале payload) и подпись (она идет в конце)
    final message = bytes.sublist(0, bytes.length - signatureLength);
    final signature = bytes.sublist(bytes.length - signatureLength);

    return PayloadPublic(
      message: message,
      signature: signature,
    );
  }

  Uint8List get standardPreAuthenticationEncoding {
    return preAuthenticationEncoding(
      header: header,
      payload: payload,
      footer: footer,
      implicit: header.version == Version.v4 || header.version == Version.v3
          ? []
          : null,
    );
  }

  Uint8List get localAADPreAuthenticationEncoding {
    final payload = payloadLocal;
    if (payload == null) throw UnsupportedError('Invalid payload.');
    final nonce = payload.nonce;
    if (nonce == null) throw UnsupportedError('Missing nonce.');
    return preAuthenticationEncoding(
      header: header,
      payload: PayloadLocal(
        secretBox: null,
        nonce: nonce,
      ),
      footer: footer,
      implicit: header.version == Version.v4 || header.version == Version.v3
          ? []
          : null,
    );
  }

  static Uint8List preAuthenticationEncoding({
    required Header header,
    required Payload payload,
    List<int>? footer,
    List<int>? implicit,
  }) {
    final components = [
      Uint8List.fromList(header.bytes),
    ];
    if (payload is PayloadLocal) {
      final nonce = payload.nonce;
      if (nonce != null) {
        components.add(Uint8List.fromList(nonce.bytes));
      }
      final secretBox = payload.secretBox;
      if (secretBox != null) {
        components.add(Uint8List.fromList(secretBox.cipherText));
      }
    } else if (payload is PayloadPublic) {
      components.add(Uint8List.fromList(payload.message));
    }
    if (footer != null) {
      components.add(Uint8List.fromList(footer));
    } else {
      components.add(Uint8List(0));
    }
    if (implicit != null) {
      components.add(Uint8List.fromList(implicit));
    }
    return _preAuthenticationEncoding(components);
  }

  static Uint8List _preAuthenticationEncoding(List<Uint8List> components) {
    return Uint8List.fromList(
      _componentLengthToByteData(components.length) +
          components.fold(
            Uint8List.fromList(<int>[]),
            (previousValue, element) =>
                previousValue +
                _componentLengthToByteData(element.length) +
                element,
          ),
    );
  }

  static Uint8List _componentLengthToByteData(int value) {
    return _componentLengthBigIntToByteData(BigInt.from(value));
  }

  static Uint8List _componentLengthBigIntToByteData(BigInt bigInt) {
    var value = bigInt.toUnsigned(64);
    final buffer = StringBuffer();
    for (var i = 0; i < 8; i++) {
      if (i == 7) {
        value = value & BigInt.from(127).toUnsigned(64);
      }
      buffer.write(
        String.fromCharCode(
          (value & BigInt.from(255).toUnsigned(64)).toInt(),
        ),
      );
      value = value >> 8;
    }
    return Uint8List.fromList(utf8.encode(buffer.toString()));
  }

  @override
  List<Object?> get props => [
        header,
        payload,
        footer,
      ];
}
