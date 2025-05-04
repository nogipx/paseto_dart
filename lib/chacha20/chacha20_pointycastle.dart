import 'dart:typed_data';
import 'package:paseto_dart/blake2/digest.dart';
import 'package:paseto_dart/blake2/ufixnum.dart';

/// All cipher initialization parameters classes implement this.
abstract class CipherParameters {}

/// [CipherParameters] consisting of an underlying [CipherParameters] (of type [UnderlyingParameters]) and an initialization
/// vector of arbitrary length.
class ParametersWithIV<UnderlyingParameters extends CipherParameters?>
    implements CipherParameters {
  final Uint8List iv;
  final UnderlyingParameters? parameters;

  ParametersWithIV(this.parameters, this.iv);
}

/// [CipherParameters] consisting of just a key of arbitrary length.
class KeyParameter extends CipherParameters {
  late Uint8List key;

  KeyParameter(this.key);

  KeyParameter.offset(Uint8List key, int keyOff, int keyLen) {
    this.key = Uint8List(keyLen);
    arrayCopy(key, keyOff, this.key, 0, keyLen);
  }

  void arrayCopy(Uint8List? sourceArr, int sourcePos, Uint8List? outArr,
      int outPos, int len) {
    for (var i = 0; i < len; i++) {
      outArr![outPos + i] = sourceArr![sourcePos + i];
    }
  }
}

/// The interface stream ciphers conform to.
abstract class StreamCipher extends Algorithm {
  /// Reset the cipher to its original state.
  void reset();

  /// Init the cipher with its initialization [params]. The type of
  /// [CipherParameters] depends on the algorithm being used (see the
  /// documentation of each implementation to find out more).
  ///
  /// Use the argument [forEncryption] to tell the cipher if you want to encrypt
  /// or decrypt data.
  void init(bool forEncryption, CipherParameters? params);

  /// Process a whole block of [data] at once, returning the result in a byte array.
  Uint8List process(Uint8List data);

  /// Process one byte of data given by [inp] and return its encrypted value.
  int returnByte(int inp);

  /// Process [len] bytes of data given by [inp] and starting at offset [inpOff].
  /// The resulting cipher text is put in [out] beginning at position [outOff].
  void processBytes(
      Uint8List inp, int inpOff, int len, Uint8List out, int outOff);
}

/// Base implementation of [StreamCipher] which provides shared methods.
abstract class BaseStreamCipher implements StreamCipher {
  @override
  Uint8List process(Uint8List data) {
    var out = Uint8List(data.length);
    processBytes(data, 0, data.length, out, 0);
    return out;
  }
}

/// Implementation of Daniel J. Bernstein's ChaCha20 stream cipher, Snuffle 2005.
class ChaCha20 extends BaseStreamCipher {
  static const STATE_SIZE = 16;

  int rounds = 20;

  static final _sigma = Uint8List.fromList([
    101,
    120,
    112,
    97,
    110,
    100,
    32,
    51,
    50,
    45,
    98,
    121,
    116,
    101,
    32,
    107
  ]);
  static final _tau = Uint8List.fromList([
    101,
    120,
    112,
    97,
    110,
    100,
    32,
    49,
    54,
    45,
    98,
    121,
    116,
    101,
    32,
    107
  ]);

  Uint8List? _workingKey;
  late Uint8List _workingIV;

  final _state = List<int>.filled(STATE_SIZE, 0, growable: false);
  final _buffer = List<int>.filled(STATE_SIZE, 0, growable: false);

  final _keyStream = Uint8List(STATE_SIZE * 4);
  var _keyStreamOffset = 0;

  var _initialised = false;

  @override
  String get algorithmName => 'ChaCha20/$rounds';

  ChaCha20() {
    rounds = 20;
  }

  ChaCha20.fromRounds(this.rounds);

  @override
  void reset() {
    if (_workingKey != null) {
      _setKey(_workingKey!, _workingIV);
    }
  }

  @override
  void init(
      bool forEncryption, covariant ParametersWithIV<KeyParameter> params) {
    var uparams = params.parameters;
    var iv = params.iv;
    if (iv.length != 8) {
      throw ArgumentError('ChaCha20 requires exactly 8 bytes of IV');
    }

    _workingIV = iv;
    _workingKey = uparams!.key;

    _setKey(_workingKey!, _workingIV);
  }

  @override
  int returnByte(int inp) {
    if (_keyStreamOffset == 0) {
      generateKeyStream(_keyStream);

      if (++_state[12] == 0) {
        ++_state[13];
      }
    }

    var out = clip8(_keyStream[_keyStreamOffset] ^ inp);
    _keyStreamOffset = (_keyStreamOffset + 1) & 63;

    return out;
  }

  @override
  void processBytes(
      Uint8List inp, int inpOff, int len, Uint8List out, int outOff) {
    if (!_initialised) {
      throw StateError('ChaCha20 not initialized: please call init() first');
    }

    if ((inpOff + len) > inp.length) {
      throw ArgumentError(
          'Input buffer too short or requested length too long');
    }

    if ((outOff + len) > out.length) {
      throw ArgumentError(
          'Output buffer too short or requested length too long');
    }

    for (var i = 0; i < len; i++) {
      if (_keyStreamOffset == 0) {
        generateKeyStream(_keyStream);

        if (++_state[12] == 0) {
          ++_state[13];
        }
      }

      out[i + outOff] = clip8(_keyStream[_keyStreamOffset] ^ inp[i + inpOff]);
      _keyStreamOffset = (_keyStreamOffset + 1) & 63;
    }
  }

  /// Метод для шифрования/дешифрования массива байтов
  @override
  Uint8List process(Uint8List data) {
    final output = Uint8List(data.length);
    processBytes(data, 0, data.length, output, 0);
    return output;
  }

  void _setKey(Uint8List keyBytes, Uint8List ivBytes) {
    _workingKey = keyBytes;
    _workingIV = ivBytes;

    _keyStreamOffset = 0;
    var offset = 0;
    Uint8List constants;

    // Key
    _state[4] = unpack32(_workingKey, 0, Endian.little);
    _state[5] = unpack32(_workingKey, 4, Endian.little);
    _state[6] = unpack32(_workingKey, 8, Endian.little);
    _state[7] = unpack32(_workingKey, 12, Endian.little);

    if (_workingKey!.length == 32) {
      constants = _sigma;
      offset = 16;
    } else {
      constants = _tau;
    }

    _state[8] = unpack32(_workingKey, offset, Endian.little);
    _state[9] = unpack32(_workingKey, offset + 4, Endian.little);
    _state[10] = unpack32(_workingKey, offset + 8, Endian.little);
    _state[11] = unpack32(_workingKey, offset + 12, Endian.little);
    _state[0] = unpack32(constants, 0, Endian.little);
    _state[1] = unpack32(constants, 4, Endian.little);
    _state[2] = unpack32(constants, 8, Endian.little);
    _state[3] = unpack32(constants, 12, Endian.little);

    // IV
    _state[14] = unpack32(_workingIV, 0, Endian.little);
    _state[15] = unpack32(_workingIV, 4, Endian.little);
    _state[12] = _state[13] = 0;

    _initialised = true;
  }

  void generateKeyStream(Uint8List output) {
    _core(rounds, _state, _buffer);
    var outOff = 0;
    for (var x in _buffer) {
      pack32(x, output, outOff, Endian.little);
      outOff += 4;
    }
  }

  /// The ChaCha20 core function
  void _core(int rounds, List<int> input, List<int> x) {
    var x00 = input[0];
    var x01 = input[1];
    var x02 = input[2];
    var x03 = input[3];
    var x04 = input[4];
    var x05 = input[5];
    var x06 = input[6];
    var x07 = input[7];
    var x08 = input[8];
    var x09 = input[9];
    var x10 = input[10];
    var x11 = input[11];
    var x12 = input[12];
    var x13 = input[13];
    var x14 = input[14];
    var x15 = input[15];

    for (var i = rounds; i > 0; i -= 2) {
      x00 += x04;
      x12 = crotl32(x12 ^ x00, 16);
      x08 += x12;
      x04 = crotl32(x04 ^ x08, 12);
      x00 += x04;
      x12 = crotl32(x12 ^ x00, 8);
      x08 += x12;
      x04 = crotl32(x04 ^ x08, 7);
      x01 += x05;
      x13 = crotl32(x13 ^ x01, 16);
      x09 += x13;
      x05 = crotl32(x05 ^ x09, 12);
      x01 += x05;
      x13 = crotl32(x13 ^ x01, 8);
      x09 += x13;
      x05 = crotl32(x05 ^ x09, 7);
      x02 += x06;
      x14 = crotl32(x14 ^ x02, 16);
      x10 += x14;
      x06 = crotl32(x06 ^ x10, 12);
      x02 += x06;
      x14 = crotl32(x14 ^ x02, 8);
      x10 += x14;
      x06 = crotl32(x06 ^ x10, 7);
      x03 += x07;
      x15 = crotl32(x15 ^ x03, 16);
      x11 += x15;
      x07 = crotl32(x07 ^ x11, 12);
      x03 += x07;
      x15 = crotl32(x15 ^ x03, 8);
      x11 += x15;
      x07 = crotl32(x07 ^ x11, 7);
      x00 += x05;
      x15 = crotl32(x15 ^ x00, 16);
      x10 += x15;
      x05 = crotl32(x05 ^ x10, 12);
      x00 += x05;
      x15 = crotl32(x15 ^ x00, 8);
      x10 += x15;
      x05 = crotl32(x05 ^ x10, 7);
      x01 += x06;
      x12 = crotl32(x12 ^ x01, 16);
      x11 += x12;
      x06 = crotl32(x06 ^ x11, 12);
      x01 += x06;
      x12 = crotl32(x12 ^ x01, 8);
      x11 += x12;
      x06 = crotl32(x06 ^ x11, 7);
      x02 += x07;
      x13 = crotl32(x13 ^ x02, 16);
      x08 += x13;
      x07 = crotl32(x07 ^ x08, 12);
      x02 += x07;
      x13 = crotl32(x13 ^ x02, 8);
      x08 += x13;
      x07 = crotl32(x07 ^ x08, 7);
      x03 += x04;
      x14 = crotl32(x14 ^ x03, 16);
      x09 += x14;
      x04 = crotl32(x04 ^ x09, 12);
      x03 += x04;
      x14 = crotl32(x14 ^ x03, 8);
      x09 += x14;
      x04 = crotl32(x04 ^ x09, 7);
    }
    var xup = [
      x00,
      x01,
      x02,
      x03,
      x04,
      x05,
      x06,
      x07,
      x08,
      x09,
      x10,
      x11,
      x12,
      x13,
      x14,
      x15
    ];
    for (var i = 0; i < STATE_SIZE; ++i) {
      x[i] = csum32(xup[i], input[i]);
    }
  }

  @override
  dynamic noSuchMethod(Invocation invocation);
}
