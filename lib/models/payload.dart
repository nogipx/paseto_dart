// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'dart:convert';

import 'package:meta/meta.dart';
import 'package:paseto_dart/paseto_dart.dart';

abstract interface class Payload {
  String get toTokenString;
}

@immutable
final class PayloadLocal implements Payload {
  const PayloadLocal({
    required this.secretBox,
    required this.nonce,
    this.mac,
  });

  final SecretBox? secretBox;
  final Mac? nonce;
  final Mac? mac;

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
    return SafeBase64.encode(result);
  }
}

@immutable
final class PayloadPublic implements Payload {
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
      return SafeBase64.encode(message + signature);
    } else {
      return SafeBase64.encode(message);
    }
  }
}
