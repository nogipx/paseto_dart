// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
// SPDX-FileCopyrightText: 2026 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: MIT

import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:equatable/equatable.dart';
import 'package:meta/meta.dart';
import 'package:paseto_dart/paseto_dart.dart';

@immutable
final class Package extends Equatable {
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
    required SecretKey preNonce,
  }) async {
    // Создаем алгоритм HMAC-SHA-384
    final hmac = Hmac(Sha384());

    // Подготавливаем данные - объединяем контент и footer если он есть
    final dataToMac = <int>[...content];
    final footer = this.footer;
    if (footer != null) {
      dataToMac.addAll(footer);
    }

    // Вычисляем MAC
    final mac = await hmac.calculateMac(
      dataToMac,
      secretKey: preNonce,
    );

    return mac;
  }

  @override
  List<Object?> get props => [
        content,
        footer,
      ];
}
