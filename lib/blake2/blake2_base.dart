import 'dart:typed_data';

/// The base class containing the shared values and methods of the
/// [Blake2b] and [Blake2s] hashing algorithms.
abstract class Blake2 {
  /// The length of the digest, defaults to `32`.
  int get digestLength;

  /// If set, [key] is used for the first round of compression.
  Uint8List? get key;

  /// If set, [salt] is used to modify the initialization vector.
  Uint8List? get salt;

  /// If set, [personalization] acts as a second [salt].
  Uint8List? get personalization;

  /// Initialization vector
  List<int>? get iv;

  /// Offsets for each round within the memory block.
  Uint8List get sigma;

  /// The hash of the key + all of the values added via `update()`.
  late List<int> _hash;

  /// The bit-length of the integers being used in the hashing function.
  ///
  /// BLAKE2b uses 64-bit, and BLAKE2s uses 32-bit.
  int get bitLength;

  /// The buffer block's length
  int get _blockSize => bitLength * 2;

  /// Buffer block
  late List<int> _block;

  /// Resets the hash to its initial state, effectively
  /// clearing all values added via `update()`.
  Blake2 reset() {
    final keyLength = (key == null) ? 0 : key!.length;

    final hash = List<int>.filled(8, 0);

    for (var i = 0; i < hash.length; i++) {
      hash[i] = iv![i];
    }

    // Модифицируем хеш с помощью соли и персонализации
    if (salt != null) {
      final saltInts = _bytesToInts(salt!, bitLength ~/ 8);
      for (var i = 0; i < saltInts.length && i < 4; i++) {
        hash[i + 4] ^= saltInts[i];
      }
    }

    if (personalization != null) {
      final persInts = _bytesToInts(personalization!, bitLength ~/ 8);
      for (var i = 0; i < persInts.length && i < 4; i++) {
        hash[i + 6] ^= persInts[i];
      }
    }

    final block = List<int>.filled(_blockSize, 0);

    if (bitLength == 32) {
      _hash = Uint32List.fromList(hash);
      _block = Uint32List.fromList(block);
    } else {
      _hash = Uint64List.fromList(hash);
      _block = Uint64List.fromList(block);
    }

    // If [key] exists, make the first round with it.
    if (keyLength > 0) {
      update(key!);
      _pointer = _blockSize;
    } else {
      _pointer = 0;
    }

    _counter = 0;

    return this;
  }

  // Преобразует байты в целые числа нужной разрядности (32 или 64 бита)
  List<int> _bytesToInts(Uint8List bytes, int bytesPerInt) {
    final ints =
        List<int>.filled((bytes.length + bytesPerInt - 1) ~/ bytesPerInt, 0);

    for (var i = 0; i < bytes.length; i++) {
      final intIndex = i ~/ bytesPerInt;
      final bytePosition = i % bytesPerInt;
      ints[intIndex] |= bytes[i] << (8 * bytePosition);
    }

    return ints;
  }

  int _pointer = 0;

  int _counter = 0;

  /// Calculates the digest of all data passed via `update()`.
  Uint8List digest() {
    final digest = Uint8List(digestLength);

    _counter += _pointer;

    // Clear block
    while (_pointer < _blockSize) {
      _block[_pointer++] = 0;
    }

    // Compress
    _compress(true);

    // Little-endian convert and store
    // Avoid out-of-bounds доступ - ограничиваем до размера _hash
    final bytesPerInt = bitLength ~/ 8;
    final maxBytes = _hash.length * bytesPerInt;
    final bytesToCopy = digestLength > maxBytes ? maxBytes : digestLength;

    for (var i = 0; i < bytesToCopy; i++) {
      final hashIndex = i ~/ bytesPerInt;
      final byteOffset = i % bytesPerInt;
      digest[i] = (_hash[hashIndex] >> (8 * byteOffset)) & 0xFF;
    }

    return digest;
  }

  /// Returns the calculated digest as a string.
  String digestToString() => String.fromCharCodes(digest());

  /// Update hash content with the given data.
  Blake2 update(Uint8List data) {
    assert(data.isNotEmpty);

    for (var i = 0; i < data.length; i++) {
      if (_pointer == _blockSize) {
        _counter += _pointer;
        _compress(false);
        _pointer = 0;
      }

      // Copy input array to input block.
      _block[_pointer++] = data[i];
    }

    return this;
  }

  /// Converts [data] to a [Uint8List] and passes it to `update()`.
  Blake2 updateWithString(String data) {
    assert(data.isNotEmpty);

    update(Uint8List.fromList(data.codeUnits));
    return this;
  }

  /// Compression function
  void _compress(bool isLast) {
    List<int> v;
    List<int> m;

    final vm = List<int>.filled(16, 0);

    if (bitLength == 32) {
      v = Uint32List.fromList(vm);
      m = Uint32List.fromList(vm);
    } else {
      v = Uint64List.fromList(vm);
      m = Uint64List.fromList(vm);
    }

    for (var i = 0; i < 8; i++) {
      v[i] = _hash[i];
      v[i + 8] = iv![i];
    }

    v[12] ^= _counter;
    if (bitLength == 32) {
      v[13] ^= (_counter >> 32);
    } else {
      v[13] ^= (_counter >> 32);
    }

    if (isLast) {
      v[14] ^= ~v[14];
    }

    // Get Little-endian words
    for (var i = 0; i < 16; i++) {
      m[i] = _get32(_block, i * 4);
    }

    void _gamma(int a, int b, int c, int d, int x, int y) {
      v[a] += v[b] + x;
      v[d] = _rotateRight(v[d] ^ v[a], 16, bitLength);

      v[c] += v[d];
      v[b] = _rotateRight(v[b] ^ v[c], 12, bitLength);

      v[a] += v[b] + y;
      v[d] = _rotateRight(v[d] ^ v[a], 8, bitLength);

      v[c] += v[d];
      v[b] = _rotateRight(v[b] ^ v[c], 7, bitLength);
    }

    final compressionRounds = (bitLength == 32) ? 10 : 12;

    for (var i = 0; i < compressionRounds; i++) {
      _gamma(0, 4, 8, 12, m[sigma[i * 16]], m[sigma[i * 16 + 1]]);
      _gamma(1, 5, 9, 13, m[sigma[i * 16 + 2]], m[sigma[i * 16 + 3]]);
      _gamma(2, 6, 10, 14, m[sigma[i * 16 + 4]], m[sigma[i * 16 + 5]]);
      _gamma(3, 7, 11, 15, m[sigma[i * 16 + 6]], m[sigma[i * 16 + 7]]);
      _gamma(0, 5, 10, 15, m[sigma[i * 16 + 8]], m[sigma[i * 16 + 9]]);
      _gamma(1, 6, 11, 12, m[sigma[i * 16 + 10]], m[sigma[i * 16 + 11]]);
      _gamma(2, 7, 8, 13, m[sigma[i * 16 + 12]], m[sigma[i * 16 + 13]]);
      _gamma(3, 4, 9, 14, m[sigma[i * 16 + 14]], m[sigma[i * 16 + 15]]);
    }

    for (var i = 0; i < 8; i++) {
      _hash[i] ^= v[i] ^ v[i + 8];
    }
  }

  /// Convert 4 bytes to Little-endian word.
  int _get32(List<int> data, int index) {
    return data[index++] ^
        (data[index++] << 8) ^
        (data[index++] << 16) ^
        (data[index] << 24);
  }

  /// Cyclic right rotation
  int _rotateRight(int data, int shift, int length) {
    return (data >> shift) ^ (data << (length - shift));
  }
}
