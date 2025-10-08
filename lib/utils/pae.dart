// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: MIT

import 'dart:typed_data';

/// Pre-Authentication Encoding (PAE) для PASETO
///
/// Реализация PAE (Pre-Authentication Encoding) согласно спецификации PASETO:
/// https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Common.md#pae-definition
///
/// PAE принимает массив байтов и кодирует их для защиты от атак канонизации.
/// Первые 8 байт содержат количество элементов в little-endian формате.
/// Затем для каждого элемента сначала записывается его длина (8 байт в little-endian),
/// а затем сам элемент.
Uint8List pae(List<Uint8List> pieces) {
  // Создаем результирующий буфер
  final count = pieces.length;

  // Считаем общую длину результата
  // 8 байт для количества элементов + (8 байт длины + длина элемента) для каждого элемента
  var totalLength = 8;
  for (final piece in pieces) {
    totalLength += 8 + piece.length;
  }

  // Создаем результирующий буфер
  final result = Uint8List(totalLength);
  var offset = 0;

  // Записываем количество элементов в little-endian формате (64 бита)
  // с установкой старшего бита в 0 для межъязыковой совместимости
  _writeLE64(result, offset, count);
  offset += 8;

  // Записываем каждый элемент
  for (final piece in pieces) {
    // Записываем длину элемента в little-endian формате (64 бита)
    _writeLE64(result, offset, piece.length);
    offset += 8;

    // Записываем сам элемент
    result.setRange(offset, offset + piece.length, piece);
    offset += piece.length;
  }

  return result;
}

/// Кодирует 64-битное целое число в little-endian формат
/// с установкой старшего бита в 0 для межъязыковой совместимости
void _writeLE64(Uint8List target, int offset, int value) {
  if (value < 0) {
    throw ArgumentError('Value must be non-negative: $value');
  }

  // Записываем младшие 7 байт как есть
  for (int i = 0; i < 7; i++) {
    target[offset + i] = (value >> (i * 8)) & 0xFF;
  }

  // Последний (самый старший) байт - с ограничением старшего бита в 0
  target[offset + 7] = (value >> 56) & 0x7F;
}
