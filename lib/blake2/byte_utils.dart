import 'dart:convert';
import 'dart:typed_data';

/// Utility functions for byte operations in Blake2.
class ByteUtils {
  /// Converts a byte array to a hex string.
  static String bytesToHex(List<int> bytes) {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  /// Converts a hex string to a byte array.
  static Uint8List hexToBytes(String hex) {
    // Normalize the hex string
    final normalizedHex = hex.replaceAll(' ', '').toLowerCase();

    // Check for valid hex string
    if (normalizedHex.length % 2 != 0) {
      throw ArgumentError('Hex string must have an even number of characters');
    }

    final bytes = Uint8List(normalizedHex.length ~/ 2);

    for (var i = 0; i < bytes.length; i++) {
      final byteHex = normalizedHex.substring(i * 2, i * 2 + 2);
      bytes[i] = int.parse(byteHex, radix: 16);
    }

    return bytes;
  }

  /// Converts a string to UTF-8 encoded bytes.
  static Uint8List stringToBytes(String str) {
    return Uint8List.fromList(utf8.encode(str));
  }

  /// Converts bytes to a UTF-8 encoded string.
  static String bytesToString(List<int> bytes) {
    return utf8.decode(bytes);
  }

  /// XOR two byte arrays of the same length.
  static Uint8List xor(List<int> a, List<int> b) {
    if (a.length != b.length) {
      throw ArgumentError('Byte arrays must have the same length');
    }

    final result = Uint8List(a.length);
    for (var i = 0; i < a.length; i++) {
      result[i] = a[i] ^ b[i];
    }

    return result;
  }

  /// Converts a number to little-endian 64-bit byte array.
  static Uint8List le64(int value) {
    final result = Uint8List(8);
    final byteData = ByteData.view(result.buffer);
    byteData.setUint64(0, value, Endian.little);
    return result;
  }

  /// Constant time comparison of two byte arrays.
  /// Returns true if the arrays are identical.
  static bool constantTimeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) {
      return false;
    }

    var result = 0;
    for (var i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }

    return result == 0;
  }
}
