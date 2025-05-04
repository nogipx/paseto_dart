// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'dart:convert';

/// Utility class for safe Base64Url operations with padding removal
/// Implements RFC4648 for Base64Url encoding
class SafeBase64 {
  /// Encodes [bytes] to Base64Url string without padding
  /// as per WebAuthn spec: Base64url with all trailing '=' characters omitted
  static String encode(List<int> bytes) {
    return base64Url.encode(bytes).replaceAll(RegExp(r'=+$'), '');
  }

  /// Decodes Base64Url [input] string with or without padding
  static List<int> decode(String input) {
    if (input.isEmpty) {
      return [];
    }

    // Преобразуем URL-safe символы в стандартные base64 символы
    String normalized = input.replaceAll('-', '+').replaceAll('_', '/');
    // Добавляем паддинг, если необходимо
    final paddedInput = _addPadding(normalized);
    return base64.decode(paddedInput);
  }

  /// Adds padding to Base64 [input] if needed to make length кратной 4
  static String _addPadding(String input) {
    // Согласно RFC4648, количество паддингов зависит от длины строки по модулю 4
    switch (input.length % 4) {
      case 0: // Длина кратна 4, паддинг не нужен
        return input;
      case 2: // Требуется 2 паддинг-символа
        return '$input==';
      case 3: // Требуется 1 паддинг-символ
        return '$input=';
      default: // Модуль 1, требуется 3 паддинг-символа - это редкий случай
        return '$input===';
    }
  }

  /// Normalizes Base64Url [input] to standard Base64 with padding
  /// This converts from WebAuthn/FIDO2 format to standard base64
  static String normalize(String input) {
    if (input.isEmpty) {
      return input;
    }

    // 1. Заменяем URL-safe символы на стандартные
    String standardBase64 = input.replaceAll('-', '+').replaceAll('_', '/');

    // 2. Добавляем паддинг в зависимости от длины строки
    // Base64 кодирует 3 байта в 4 символа, поэтому длина должна быть кратна 4
    return _addPadding(standardBase64);
  }
}
