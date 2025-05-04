import 'dart:typed_data';
import 'package:pointycastle/export.dart' as pc;

/// Вспомогательный класс для прямого шифрования XChaCha20
class XChaCha20Direct {
  const XChaCha20Direct();

  /// Шифрует данные с помощью XChaCha20
  List<int> encrypt(
    List<int> plaintext, {
    required List<int> key,
    required List<int> nonce,
  }) {
    if (nonce.length != 24) {
      throw ArgumentError('XChaCha20 requires a 24-byte nonce');
    }

    // XChaCha20 использует первые 16 байт nonce для HChaCha20,
    // а последние 8 байт (с 4 нулевыми байтами впереди) для ChaCha20
    final hChaCha20Nonce = nonce.sublist(0, 16);

    // 1. Получить производный ключ с помощью HChaCha20
    final derivedKey = _deriveHChaChaKey(key, hChaCha20Nonce);

    // 2. Создать 12-байтный nonce для ChaCha20:
    // первые 4 байта - нули, последние 8 - из последних 8 байт исходного nonce
    final chaCha20Nonce = Uint8List(12);
    for (var i = 0; i < 8; i++) {
      chaCha20Nonce[i + 4] = nonce[i + 16];
    }

    // 3. Шифрование с помощью ChaCha20
    final cipher = pc.StreamCipher('ChaCha7539');
    final params = pc.ParametersWithIV(
        pc.KeyParameter(Uint8List.fromList(derivedKey)), chaCha20Nonce);
    cipher.init(true, params);

    final cipherText = Uint8List(plaintext.length);
    for (var i = 0; i < plaintext.length; i++) {
      cipherText[i] = cipher.returnByte(plaintext[i]);
    }

    return cipherText.toList();
  }

  /// Расшифровывает данные с помощью XChaCha20
  List<int> decrypt(
    List<int> ciphertext, {
    required List<int> key,
    required List<int> nonce,
  }) {
    if (nonce.length != 24) {
      throw ArgumentError('XChaCha20 requires a 24-byte nonce');
    }

    // XChaCha20 использует первые 16 байт nonce для HChaCha20,
    // а последние 8 байт (с 4 нулевыми байтами впереди) для ChaCha20
    final hChaCha20Nonce = nonce.sublist(0, 16);

    // 1. Получить производный ключ с помощью HChaCha20
    final derivedKey = _deriveHChaChaKey(key, hChaCha20Nonce);

    // 2. Создать 12-байтный nonce для ChaCha20:
    // первые 4 байта - нули, последние 8 - из последних 8 байт исходного nonce
    final chaCha20Nonce = Uint8List(12);
    for (var i = 0; i < 8; i++) {
      chaCha20Nonce[i + 4] = nonce[i + 16];
    }

    // 3. Расшифрование с помощью ChaCha20
    final cipher = pc.StreamCipher('ChaCha7539');
    final params = pc.ParametersWithIV(
        pc.KeyParameter(Uint8List.fromList(derivedKey)), chaCha20Nonce);
    cipher.init(false, params);

    final plainText = Uint8List(ciphertext.length);
    for (var i = 0; i < ciphertext.length; i++) {
      plainText[i] = cipher.returnByte(ciphertext[i]);
    }

    return plainText.toList();
  }

  /// Создает HChaCha20 промежуточный ключ из основного ключа и первых 16 байт nonce
  List<int> _deriveHChaChaKey(List<int> key, List<int> nonce) {
    // ChaCha20 константы (литералы "expand 32-byte k" в little-endian)
    final state = List<int>.filled(16, 0);
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Заполняем состояние ключом (8 слов)
    for (int i = 0; i < 8; i++) {
      state[i + 4] = _bytesToWord(key, i * 4);
    }

    // Заполняем состояние nonce (4 слова)
    for (int i = 0; i < 4; i++) {
      state[i + 12] = _bytesToWord(nonce, i * 4);
    }

    // Выполняем 20 раундов ChaCha20
    _chachaRounds(state);

    // В отличие от ChaCha20, HChaCha20 возвращает
    // первые 4 слова и последние 4 слова состояния
    final result = Uint8List(32);
    for (int i = 0; i < 4; i++) {
      _wordToBytes(state[i], result, i * 4);
      _wordToBytes(state[i + 12], result, (i + 4) * 4);
    }

    return result.toList();
  }

  // Преобразует 4 байта в 32-битное слово (little-endian)
  int _bytesToWord(List<int> bytes, int offset) {
    return (bytes[offset] & 0xFF) |
        ((bytes[offset + 1] & 0xFF) << 8) |
        ((bytes[offset + 2] & 0xFF) << 16) |
        ((bytes[offset + 3] & 0xFF) << 24);
  }

  // Преобразует 32-битное слово в 4 байта (little-endian)
  void _wordToBytes(int word, Uint8List bytes, int offset) {
    bytes[offset] = word & 0xFF;
    bytes[offset + 1] = (word >> 8) & 0xFF;
    bytes[offset + 2] = (word >> 16) & 0xFF;
    bytes[offset + 3] = (word >> 24) & 0xFF;
  }

  // Выполняет раунды ChaCha20
  void _chachaRounds(List<int> state) {
    // Сохраняем исходное состояние
    final x = List<int>.from(state);

    // 20 раундов (10 двойных раундов)
    for (int i = 0; i < 10; i++) {
      // Вертикальные четверки
      _quarterRound(x, 0, 4, 8, 12);
      _quarterRound(x, 1, 5, 9, 13);
      _quarterRound(x, 2, 6, 10, 14);
      _quarterRound(x, 3, 7, 11, 15);

      // Диагональные четверки
      _quarterRound(x, 0, 5, 10, 15);
      _quarterRound(x, 1, 6, 11, 12);
      _quarterRound(x, 2, 7, 8, 13);
      _quarterRound(x, 3, 4, 9, 14);
    }

    // Копируем результат обратно в состояние
    for (int i = 0; i < 16; i++) {
      state[i] = x[i];
    }
  }

  // Квартер-раунд ChaCha20
  void _quarterRound(List<int> x, int a, int b, int c, int d) {
    x[a] = _add32(x[a], x[b]);
    x[d] = _rotl32(x[d] ^ x[a], 16);

    x[c] = _add32(x[c], x[d]);
    x[b] = _rotl32(x[b] ^ x[c], 12);

    x[a] = _add32(x[a], x[b]);
    x[d] = _rotl32(x[d] ^ x[a], 8);

    x[c] = _add32(x[c], x[d]);
    x[b] = _rotl32(x[b] ^ x[c], 7);
  }

  // Сложение по модулю 2^32
  int _add32(int a, int b) {
    return (a + b) & 0xFFFFFFFF;
  }

  // Циклический сдвиг влево
  int _rotl32(int x, int n) {
    return ((x << n) & 0xFFFFFFFF) | ((x & 0xFFFFFFFF) >> (32 - n));
  }
}
