// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'dart:convert';
import 'dart:typed_data';

import 'package:equatable/equatable.dart';
import 'package:meta/meta.dart';
import 'package:paseto_dart/paseto_dart.dart';
import 'package:pointycastle/export.dart' as pc;

@immutable
class Package extends Equatable {
  const Package({
    required this.content,
    this.footer,
  });

  final List<int> content;
  final List<int>? footer;

  String get stringContent {
    try {
      return utf8.decode(content);
    } catch (e) {
      return String.fromCharCodes(content);
    }
  }

  Map<String, dynamic>? get jsonContent {
    try {
      return jsonDecode(stringContent) as Map<String, dynamic>;
    } catch (e) {
      return null;
    }
  }

  String? get stringFooter {
    final footer = this.footer;
    if (footer == null) return null;
    try {
      return utf8.decode(footer);
    } catch (e) {
      return String.fromCharCodes(footer);
    }
  }

  Map<String, dynamic>? get jsonFooter {
    final stringFooter = this.stringFooter;
    if (stringFooter == null) return null;
    try {
      return jsonDecode(stringFooter) as Map<String, dynamic>;
    } catch (e) {
      return null;
    }
  }

  Future<Mac> calculateNonce({
    required SecretKeyData preNonce,
  }) async {
    final pc.HMac hmac = pc.HMac(pc.SHA384Digest(), 128);
    hmac.init(
        pc.KeyParameter(Uint8List.fromList(await preNonce.extractBytes())));

    hmac.update(Uint8List.fromList(content), 0, content.length);
    final footer = this.footer;
    if (footer != null) {
      hmac.update(Uint8List.fromList(footer), 0, footer.length);
    }

    final nonceBytes = Uint8List(hmac.macSize);
    hmac.doFinal(nonceBytes, 0);

    return Mac(nonceBytes.toList());
  }

  @override
  List<Object?> get props => [
        content,
        footer,
      ];
}
