import 'dart:convert';

import 'package:meta/meta.dart';
import 'package:paseto_dart/paseto_dart.dart';

abstract class Payload {
  String get toTokenString;
}

@immutable
class PayloadLocal implements Payload {
  const PayloadLocal({
    required this.secretBox,
    required this.nonce,
    this.mac,
  });

  final SecretBox? secretBox;
  final Mac? nonce;
  final Hash? mac;

  @override
  String get toTokenString {
    var result = List<int>.empty(growable: true);
    final nonce = this.nonce;
    if (nonce != null) {
      result += nonce.bytes;
    }
    final secretBox = this.secretBox;
    if (secretBox != null) {
      result += secretBox.cipherText;
    }
    final mac = this.mac;
    if (mac != null) {
      result += mac.bytes;
    }
    return encodePasetoBase64(result);
  }
}

@immutable
class PayloadPublic implements Payload {
  const PayloadPublic({
    required this.message,
    this.signature,
  });

  final List<int> message;
  final List<int>? signature;

  /// Декодирует содержимое сообщения в строку UTF-8
  String get stringMessage => utf8.decode(message);

  /// Декодирует содержимое сообщения как JSON, если возможно
  Map<String, dynamic>? get jsonContent {
    try {
      return json.decode(stringMessage) as Map<String, dynamic>;
    } catch (e) {
      return null;
    }
  }

  @override
  String get toTokenString {
    final signature = this.signature;
    if (signature != null) {
      return encodePasetoBase64(message + signature);
    } else {
      return encodePasetoBase64(message);
    }
  }
}
