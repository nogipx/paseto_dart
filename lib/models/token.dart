// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'dart:convert';
import 'dart:typed_data';

import 'package:equatable/equatable.dart';
import 'package:meta/meta.dart';
import 'package:paseto_dart/paseto_dart.dart';
import 'package:paseto_dart/utils/pae.dart';

@immutable
final class Token extends Equatable {
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
      tokenString += '.${SafeBase64.encode(footer)}';
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
      case Version.v4:
        return LocalV4.decrypt(
          this,
          secretKey: secretKey,
          implicit: implicit,
        );
    }
  }

  Future<Message> verifyPublicMessage({
    required SimplePublicKey publicKey,
    List<int>? implicit,
  }) async {
    if (header.purpose != Purpose.public) {
      throw UnsupportedError('Unable to verify non-public message');
    }
    return Message(
      header: header,
      package: await _verifyPackage(
        publicKey: publicKey,
        implicit: implicit,
      ),
      payload: payload,
    );
  }

  Future<Package> _verifyPackage({
    required SimplePublicKey publicKey,
    List<int>? implicit,
  }) async {
    switch (header.version) {
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
      footer: components.length > 3 ? SafeBase64.decode(components[3]) : null,
    );
  }

  static Payload decodePayload(
    String string, {
    required Header header,
  }) {
    final bytes = SafeBase64.decode(string);

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

    // Определяем длину nonce для версии
    switch (version) {
      case Version.v4:
        nonceLength = LocalV4.nonceLength;
        break;
    }

    // Проверяем минимальную длину payload
    if (bytes.length < nonceLength) {
      throw FormatException(
          'Invalid token payload length for ${version.name}.local: expected at least $nonceLength bytes, got ${bytes.length}');
    }

    // ИСПРАВЛЕНО согласно официальной спецификации PASETO v4.local:
    // payload format = nonce || ciphertext (БЕЗ MAC!)
    // MAC вычисляется отдельно и НЕ хранится в payload

    // Извлекаем nonce (первые 32 байта)
    final nonce = bytes.sublist(0, nonceLength);

    // Извлекаем ciphertext (все оставшиеся байты)
    final ciphertext = bytes.sublist(nonceLength);

    return PayloadLocal(
      nonce: Mac(nonce),
      secretBox: SecretBox(ciphertext,
          nonce: Uint8List.fromList(nonce.sublist(0, 12)),
          mac: Mac(Uint8List(0))),
      mac: null, // MAC НЕ хранится в payload согласно спецификации!
      payloadBytes: bytes, // Сохраняем исходные байты
    );
  }

  static Payload _decodePublicPayload(List<int> bytes, Version version) {
    int signatureLength = 0;

    // Определяем длину подписи для версии
    switch (version) {
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
      implicit: header.version == Version.v4 ? [] : null,
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
      implicit: header.version == Version.v4 ? [] : null,
    );
  }

  static Uint8List preAuthenticationEncoding({
    required Header header,
    required Payload payload,
    required List<int>? footer,
    List<int>? implicit,
  }) {
    final headerString = [header.version.name, header.purpose.name].join('.');
    final headerComponent = Uint8List.fromList(utf8.encode(headerString));

    // Формируем payload данные
    final payloadComponent = switch (payload) {
      PayloadLocal() => Uint8List.fromList(payload.nonce?.bytes ?? []),
      PayloadPublic() => Uint8List.fromList(payload.message),
      _ => Uint8List(0),
    };

    final footerComponent = Uint8List.fromList(footer ?? []);
    final implicitComponent = Uint8List.fromList(implicit ?? []);

    final result = pae([
      headerComponent,
      payloadComponent,
      footerComponent,
      implicitComponent,
    ]);

    return result;
  }

  @override
  List<Object?> get props => [
        header,
        payload,
        footer,
      ];
}
