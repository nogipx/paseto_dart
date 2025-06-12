// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'dart:typed_data';

import 'digest.dart';
import 'ufixnum.dart';

/// Base implementation of [Digest] which provides shared methods.
abstract class BaseDigest implements Digest {
  @override
  Uint8List process(Uint8List data) {
    update(data, 0, data.length);
    var out = Uint8List(digestSize);
    var len = doFinal(out, 0);
    return out.sublist(0, len);
  }
}

/// Реализация алгоритма хеширования BLAKE2b.
///
/// BLAKE2b - это криптографическая хеш-функция, оптимизированная для 64-битных платформ.
/// Данная реализация адаптирована из библиотеки PointyCastle для использования в PASETO.
/// Поддерживает длину дайджеста от 1 до 64 байт, ключи, соль и персонализацию.
///
/// Соответствует спецификации RFC 7693.
class Blake2b extends BaseDigest implements Digest {
  /// Количество раундов обработки в функции сжатия
  static const _rounds = 12;

  /// Размер блока в байтах (128 байт для BLAKE2b)
  static const _blockSize = 128;

  /// Длина выходного дайджеста в байтах (по умолчанию 64 байта = 512 бит)
  int _digestLength = 64;

  /// Длина ключа, если используется
  int _keyLength = 0;

  /// Соль для персонализации хеша (опционально, 16 байт)
  Uint8List? _salt;

  /// Персонализация хеша (опционально, 16 байт)
  Uint8List? _personalization;

  /// Ключ для хеширования (опционально, до 64 байт)
  Uint8List? _key;

  /// Внутренний буфер для накопления данных до полного блока
  Uint8List? _buffer;

  /// Позиция последнего вставленного байта в буфере
  int _bufferPos = 0; // значение от 0 до 128

  /// Внутреннее состояние во время обработки (вектор v в документации BLAKE2b)
  final _internalState = Register64List(16);

  /// Цепное значение (вектор h в документации BLAKE2b)
  Register64List? _chainValue;

  /// Счетчик байтов (младшие биты)
  final _t0 = Register64();

  /// Счетчик байтов (старшие биты, для обработки сообщений > 2^64 байт)
  final _t1 = Register64();

  /// Флаг финализации для последнего блока
  final _f0 = Register64();

  /// Создает новый экземпляр BLAKE2b.
  ///
  /// [digestSize] - длина дайджеста в байтах (1-64), по умолчанию 64.
  /// [key] - опциональный ключ для хеширования (макс. 64 байта).
  /// [salt] - опциональная соль (ровно 16 байт).
  /// [personalization] - опциональная персонализация (ровно 16 байт).
  Blake2b(
      {int digestSize = 64,
      Uint8List? key,
      Uint8List? salt,
      Uint8List? personalization}) {
    _buffer = Uint8List(_blockSize);

    if (digestSize < 1 || digestSize > 64) {
      throw ArgumentError('Invalid digest length (required: 1 - 64)');
    }
    _digestLength = digestSize;
    if (salt != null) {
      if (salt.length != 16) {
        throw ArgumentError('salt length must be exactly 16 bytes');
      }
      _salt = Uint8List.fromList(salt);
    }
    if (personalization != null) {
      if (personalization.length != 16) {
        throw ArgumentError('personalization length must be exactly 16 bytes');
      }
      _personalization = Uint8List.fromList(personalization);
    }
    if (key != null) {
      if (key.length > 64) throw ArgumentError('Keys > 64 are not supported');
      _key = Uint8List.fromList(key);

      _keyLength = key.length;
      _buffer!.setAll(0, key);
      _bufferPos = _blockSize;
    }
    init();
  }

  /// Возвращает название алгоритма ('Blake2b')
  @override
  String get algorithmName => 'Blake2b';

  /// Возвращает размер дайджеста в байтах
  @override
  int get digestSize => _digestLength;

  /// Инициализирует внутреннее состояние хеша.
  ///
  /// Создает и настраивает цепное значение с использованием IV, длины дайджеста,
  /// длины ключа, соли и персонализации в соответствии со спецификацией BLAKE2b.
  void init() {
    if (_chainValue == null) {
      _chainValue = Register64List(8);
      _chainValue![0]
        ..set(_blake2bIV[0])
        ..xor(Register64(digestSize | (_keyLength << 8) | 0x1010000));
      _chainValue![1].set(_blake2bIV[1]);
      _chainValue![2].set(_blake2bIV[2]);

      _chainValue![3].set(_blake2bIV[3]);

      _chainValue![4].set(_blake2bIV[4]);
      _chainValue![5].set(_blake2bIV[5]);
      if (_salt != null) {
        _chainValue![4].xor(Register64()..unpack(_salt, 0, Endian.little));
        _chainValue![5].xor(Register64()..unpack(_salt, 8, Endian.little));
      }

      _chainValue![6].set(_blake2bIV[6]);
      _chainValue![7].set(_blake2bIV[7]);
      if (_personalization != null) {
        _chainValue![6]
            .xor(Register64()..unpack(_personalization, 0, Endian.little));
        _chainValue![7]
            .xor(Register64()..unpack(_personalization, 8, Endian.little));
      }
    }
  }

  /// Инициализирует внутреннее состояние перед сжатием.
  ///
  /// Подготавливает вектор v для функции сжатия, копируя в него
  /// цепное значение h, IV и счетчики с необходимыми XOR операциями.
  void _initializeInternalState() {
    _internalState.setRange(0, _chainValue!.length, _chainValue!);
    _internalState.setRange(
        _chainValue!.length, _chainValue!.length + 4, _blake2bIV);
    _internalState[12]
      ..set(_t0)
      ..xor(_blake2bIV[4]);
    _internalState[13]
      ..set(_t1)
      ..xor(_blake2bIV[5]);
    _internalState[14]
      ..set(_f0)
      ..xor(_blake2bIV[6]);
    _internalState[15].set(_blake2bIV[7]); // ^ f1 with f1 = 0
  }

  /// Обновляет хеш одним байтом.
  ///
  /// Добавляет один байт данных к текущему хешу.
  /// Если буфер заполнен, выполняет сжатие и очищает буфер.
  ///
  /// [inp] - Входной байт для добавления к хешу.
  @override
  void updateByte(int inp) {
    if (_bufferPos == _blockSize) {
      // full buffer
      _t0.sum(_blockSize);
      // This requires hashing > 2^64 bytes which is impossible for the forseeable future.
      // So _t1 is untested dead code, but I've left it in because it is in the source library.
      if (_t0.lo32 == 0 && _t0.hi32 == 0) _t1.sum(1);
      _compress(_buffer, 0);
      _buffer!.fillRange(0, _buffer!.length, 0); // clear buffer
      _buffer![0] = inp;
      _bufferPos = 1;
    } else {
      _buffer![_bufferPos] = inp;
      ++_bufferPos;
    }
  }

  /// Обновляет хеш блоком данных.
  ///
  /// Добавляет блок данных к текущему хешу, обрабатывая его по частям
  /// размером с блок. Эффективно обрабатывает большие объемы данных.
  ///
  /// [inp] - Входной массив данных.
  /// [inpOff] - Начальное смещение в массиве.
  /// [len] - Количество байт для обработки.
  @override
  void update(Uint8List inp, int inpOff, int len) {
    if (len == 0) return;
    var remainingLength = 0;
    if (_bufferPos != 0) {
      remainingLength = _blockSize - _bufferPos;
      if (remainingLength < len) {
        _buffer!
            .setRange(_bufferPos, _bufferPos + remainingLength, inp, inpOff);
        _t0.sum(_blockSize);
        if (_t0.lo32 == 0 && _t0.hi32 == 0) _t1.sum(1);
        _compress(_buffer, 0);
        _bufferPos = 0;
        _buffer!.fillRange(0, _buffer!.length, 0); // clear buffer
      } else {
        _buffer!.setRange(_bufferPos, _bufferPos + len, inp, inpOff);
        _bufferPos += len;
        return;
      }
    }

    int msgPos;
    var blockWiseLastPos = inpOff + len - _blockSize;
    for (msgPos = inpOff + remainingLength;
        msgPos < blockWiseLastPos;
        msgPos += _blockSize) {
      _t0.sum(_blockSize);
      if (_t0.lo32 == 0 && _t0.hi32 == 0) _t1.sum(1);
      _compress(inp, msgPos);
    }

    _buffer!.setRange(0, inpOff + len - msgPos, inp, msgPos);
    _bufferPos += inpOff + len - msgPos;
  }

  /// Завершает хеширование и возвращает итоговый дайджест.
  ///
  /// Обрабатывает последний блок с установленным флагом финализации,
  /// выполняет окончательное сжатие и формирует выходной дайджест.
  ///
  /// [out] - Выходной буфер для записи результата.
  /// [outOff] - Начальное смещение в выходном буфере.
  ///
  /// Возвращает длину сгенерированного дайджеста в байтах.
  @override
  int doFinal(Uint8List out, int outOff) {
    _f0.set(0xFFFFFFFF, 0xFFFFFFFF);
    _t0.sum(_bufferPos);
    if (_bufferPos > 0 && _t0.lo32 == 0 && _t0.hi32 == 0) _t1.sum(1);
    _compress(_buffer, 0);
    _buffer!.fillRange(0, _buffer!.length, 0); // clear buffer
    _internalState.fillRange(0, _internalState.length, 0);

    final packedValue = Uint8List(8);
    final packedValueData = packedValue.buffer.asByteData();
    for (var i = 0; i < _chainValue!.length && (i * 8 < _digestLength); ++i) {
      _chainValue![i].pack(packedValueData, 0, Endian.little);

      final start = outOff + i * 8;
      if (i * 8 < _digestLength - 8) {
        out.setRange(start, start + 8, packedValue);
      } else {
        out.setRange(start, start + _digestLength - (i * 8), packedValue);
      }
    }

    _chainValue!.fillRange(0, _chainValue!.length, 0);

    reset();

    return _digestLength;
  }

  /// Сбрасывает хеш до начального состояния.
  ///
  /// Очищает буфер и внутреннее состояние, сбрасывает счетчики
  /// и инициализирует хеш для новой операции хеширования.
  /// Если был установлен ключ, восстанавливает его в буфере.
  @override
  void reset() {
    _bufferPos = 0;
    _f0.set(0);
    _t0.set(0);
    _t1.set(0);
    _chainValue = null;
    _buffer!.fillRange(0, _buffer!.length, 0);
    if (_key != null) {
      _buffer!.setAll(0, _key!);
      _bufferPos = _blockSize;
    }
    init();
  }

  // Временная переменная для функции сжатия
  final _m = Register64List(16);

  /// Выполняет основную функцию сжатия BLAKE2b.
  ///
  /// Это ядро алгоритма, которое обрабатывает один блок данных.
  /// Преобразует 128-байтный блок в слова, выполняет все раунды перемешивания
  /// и обновляет цепное значение.
  ///
  /// [message] - Сообщение для сжатия.
  /// [messagePos] - Начальная позиция блока в сообщении.
  void _compress(Uint8List? message, int messagePos) {
    _initializeInternalState();

    for (var j = 0; j < 16; ++j) {
      _m[j].unpack(message, messagePos + j * 8, Endian.little);
    }

    for (var round = 0; round < _rounds; ++round) {
      G(_m[_blake2bSigma[round][0]], _m[_blake2bSigma[round][1]], 0, 4, 8, 12);
      G(_m[_blake2bSigma[round][2]], _m[_blake2bSigma[round][3]], 1, 5, 9, 13);
      G(_m[_blake2bSigma[round][4]], _m[_blake2bSigma[round][5]], 2, 6, 10, 14);
      G(_m[_blake2bSigma[round][6]], _m[_blake2bSigma[round][7]], 3, 7, 11, 15);
      G(_m[_blake2bSigma[round][8]], _m[_blake2bSigma[round][9]], 0, 5, 10, 15);
      G(_m[_blake2bSigma[round][10]], _m[_blake2bSigma[round][11]], 1, 6, 11,
          12);
      G(_m[_blake2bSigma[round][12]], _m[_blake2bSigma[round][13]], 2, 7, 8,
          13);
      G(_m[_blake2bSigma[round][14]], _m[_blake2bSigma[round][15]], 3, 4, 9,
          14);
    }

    for (var offset = 0; offset < _chainValue!.length; ++offset) {
      _chainValue![offset]
        ..xor(_internalState[offset])
        ..xor(_internalState[offset + 8]);
    }
  }

  /// Функция перемешивания G из спецификации BLAKE2b.
  ///
  /// Выполняет одну операцию перемешивания над четырьмя ячейками внутреннего состояния.
  /// Является основным криптографическим примитивом алгоритма.
  ///
  /// [m1], [m2] - Входные слова сообщения.
  /// [posA], [posB], [posC], [posD] - Позиции ячеек в векторе состояния.
  void G(Register64 m1, Register64 m2, int posA, int posB, int posC, int posD) {
    // This variable is faster as a local. The allocation is probably sunk.
    final r = Register64();

    _internalState[posA].sumReg(r
      ..set(_internalState[posB])
      ..sumReg(m1));
    _internalState[posD]
      ..xor(_internalState[posA])
      ..rotr(32);
    _internalState[posC].sumReg(_internalState[posD]);
    _internalState[posB]
      ..xor(_internalState[posC])
      ..rotr(24);
    _internalState[posA].sumReg(r
      ..set(_internalState[posB])
      ..sumReg(m2));
    _internalState[posD]
      ..xor(_internalState[posA])
      ..rotr(16);
    _internalState[posC].sumReg(_internalState[posD]);
    _internalState[posB]
      ..xor(_internalState[posC])
      ..rotr(63);
  }

  /// Возвращает размер блока в байтах (128 для BLAKE2b).
  ///
  /// Это внутренний параметр, используемый для оптимизации производительности.
  @override
  int get byteLength => 128;

  /// Удобный метод для синхронного хеширования данных.
  ///
  /// Выполняет полное хеширование входных данных за один вызов.
  /// Эквивалентно созданию нового экземпляра, добавлению данных
  /// и вызову doFinal.
  ///
  /// [data] - Данные для хеширования.
  ///
  /// Возвращает результат хеширования.
  Uint8List hashSync(List<int> data) {
    final inputData = data is Uint8List ? data : Uint8List.fromList(data);
    return process(inputData);
  }

  /// Удобный метод для добавления данных в поток.
  ///
  /// Добавляет данные к текущему состоянию хеша.
  /// Можно вызывать многократно для инкрементального хеширования.
  ///
  /// [data] - Данные для добавления к хешу.
  void addSync(List<int> data) {
    final inputData = data is Uint8List ? data : Uint8List.fromList(data);
    update(inputData, 0, inputData.length);
  }

  /// Удобный метод для получения финального хеша.
  ///
  /// Завершает процесс хеширования и возвращает результат.
  /// После вызова этого метода хеш сбрасывается в начальное состояние.
  ///
  /// Возвращает финальный дайджест.
  Uint8List digestSync() {
    final result = Uint8List(digestSize);
    doFinal(result, 0);
    return result;
  }

  /// Возвращает инициализационный вектор BLAKE2b.
  ///
  /// Этот статический метод предоставляет доступ к стандартному
  /// инициализационному вектору BLAKE2b.
  static Register64List get blake2bIV => _blake2bIV;
}

/// Инициализационный вектор BLAKE2b.
///
/// Получен из квадратных корней первых 8 простых чисел.
/// Совпадает с инициализационным вектором SHA-512.
final _blake2bIV = Register64List.from([
  [0x6a09e667, 0xf3bcc908],
  [0xbb67ae85, 0x84caa73b],
  [0x3c6ef372, 0xfe94f82b],
  [0xa54ff53a, 0x5f1d36f1],
  [0x510e527f, 0xade682d1],
  [0x9b05688c, 0x2b3e6c1f],
  [0x1f83d9ab, 0xfb41bd6b],
  [0x5be0cd19, 0x137e2179],
]);

/// Таблица перестановок для функции сжатия BLAKE2b.
///
/// Определяет порядок выбора слов сообщения в каждом раунде
/// для обеспечения криптографических свойств алгоритма.
final _blake2bSigma = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];
