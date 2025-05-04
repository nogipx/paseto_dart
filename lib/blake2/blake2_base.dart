import 'dart:typed_data';
import 'package:meta/meta.dart';

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

  /// The bit-length of the integers being used in the hashing function.
  ///
  /// BLAKE2b uses 64-bit, and BLAKE2s uses 32-bit.
  int get bitLength;

  /// The buffer block's length - for internal use by derived classes
  @protected
  int get blockSize => bitLength * 2;

  /// Buffer block
  @protected
  late List<int> block;

  /// Position in the current block
  @protected
  int pointer = 0;

  /// Counter for bytes processed
  @protected
  int counter = 0;

  /// Resets the hash to its initial state, effectively
  /// clearing all values added via `update()`.
  Blake2 reset() {
    block = List<int>.filled(blockSize, 0);
    return this;
  }

  /// Calculates the digest of all data passed via `update()`.
  Uint8List digest();

  /// Compression function
  @protected
  void compress(bool isLast);

  /// Returns the calculated digest as a string.
  String digestToString() => String.fromCharCodes(digest());

  /// Update hash content with the given data.
  Blake2 update(Uint8List data) {
    // Если данные пустые, просто возвращаем текущее состояние
    if (data.isEmpty) {
      return this;
    }

    for (var i = 0; i < data.length; i++) {
      if (pointer == blockSize) {
        counter += pointer;
        compress(false);
        pointer = 0;
      }

      // Copy input array to input block.
      block[pointer++] = data[i];
    }

    return this;
  }

  /// Converts [data] to a [Uint8List] and passes it to `update()`.
  Blake2 updateWithString(String data) {
    update(Uint8List.fromList(data.codeUnits));
    return this;
  }
}
