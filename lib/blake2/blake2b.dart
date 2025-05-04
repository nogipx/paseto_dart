import 'dart:typed_data';
import 'blake2_base.dart';

/// The BLAKE2b (64-bit) flavor of the BLAKE2
/// cryptographic hash function.
/// Implementation follows the RFC 7693 specification
/// https://www.rfc-editor.org/rfc/rfc7693.txt
class Blake2b extends Blake2 {
  /// Creates a BLAKE2b hash instance.
  ///
  /// [digestLength] specifies the length of the output hash in bytes.
  /// It must be > 0 and <= 64.
  ///
  /// [key] may be null, but if set, it will be used for the
  /// first round of compression.
  ///
  /// [salt] and [personalization] may be null or must be 16 bytes in length.
  Blake2b({
    this.digestLength = 32,
    this.key,
    this.salt,
    this.personalization,
  })  : assert(digestLength > 0 && digestLength <= 64),
        assert(salt == null || salt.length == 16),
        assert(personalization == null || personalization.length == 16) {
    reset();
  }

  @override
  final Uint8List? key;

  @override
  final Uint8List? salt;

  @override
  final Uint8List? personalization;

  @override
  final int digestLength;

  /// Внутреннее состояние хеша (h)
  late Uint64List _h;

  /// Счетчики байтов, обработанных до текущего момента
  late Uint64List _t;

  /// Флаг последнего блока (для остановки сжатия)
  late bool _f;

  @override
  List<int>? get iv => _h.toList();

  @override
  final int bitLength = 64;

  /// Размер блока для Blake2b
  int get blockSize => bitLength * 2;

  @override
  Blake2b reset() {
    super.reset();

    // Инициализация векторов состояния
    _h = Uint64List.fromList(_iv);
    _t = Uint64List(2);
    _f = false;

    // Параметрический блок (64 байта) для инициализации
    final p = Uint8List(64);

    // Настройка параметров по RFC 7693 (секция 2.8)
    p[0] = digestLength; // digest length
    p[1] = key?.length ?? 0; // key length
    p[2] = 1; // fanout
    p[3] = 1; // depth

    // Если есть соль, копируем её (байты 32-47)
    if (salt != null) {
      for (var i = 0; i < salt!.length; i++) {
        p[32 + i] = salt![i];
      }
    }

    // Если есть персонализация, копируем её (байты 48-63)
    if (personalization != null) {
      for (var i = 0; i < personalization!.length; i++) {
        p[48 + i] = personalization![i];
      }
    }

    // XOR параметров с IV
    for (var i = 0; i < 8; i++) {
      _h[i] ^= _load64(p, i * 8);
    }

    // Обработка ключа, если он есть
    if (key != null && key!.isNotEmpty) {
      // Создаем блок для ключа размером 128 байт (blockSize)
      final keyBlock = Uint8List(128);

      // Копируем ключ в начало блока
      for (var i = 0; i < key!.length; i++) {
        keyBlock[i] = key![i];
      }

      // Обновляем хеш с блоком ключа
      update(keyBlock);

      // Обнуляем указатель блока
      pointer = 0;
    }

    return this;
  }

  @override
  Uint8List digest() {
    final out = Uint8List(digestLength);
    final buffer = Uint8List(128);

    // Копируем оставшиеся байты из текущего блока
    for (var i = 0; i < pointer; i++) {
      buffer[i] = block[i];
    }

    // Дополняем нулями оставшуюся часть блока
    for (var i = pointer; i < 128; i++) {
      buffer[i] = 0;
    }

    // Увеличиваем счетчик байтов
    _t[0] += pointer;
    if (_t[0] < pointer) {
      _t[1]++;
    }

    // Установка флага последнего блока
    _f = true;

    // Последнее сжатие
    _compress(buffer);

    // Копируем результат в выходной буфер в формате little-endian
    // Именно так определено в RFC 7693
    final h = _h;
    for (var i = 0; i < digestLength; i++) {
      out[i] = (h[i >> 3] >> ((i & 7) << 3)) & 0xFF;
    }

    return out;
  }

  @override
  void compress(bool isLast) {
    // Увеличиваем счетчик байтов
    _t[0] += blockSize;
    if (_t[0] < blockSize) {
      _t[1]++;
    }

    // Устанавливаем флаг последнего блока
    _f = isLast;

    // Копируем текущий блок для сжатия
    final buffer = Uint8List(128);
    for (var i = 0; i < blockSize; i++) {
      buffer[i] = block[i];
    }

    _compress(buffer);
  }

  /// Основная функция сжатия BLAKE2b
  /// Строго следует RFC 7693 (https://www.rfc-editor.org/rfc/rfc7693.txt)
  void _compress(Uint8List buffer) {
    final v = Uint64List(16);
    final m = Uint64List(16);

    // Загрузка 16 слов сообщения (каждое по 8 байт) из буфера в формате little-endian
    for (var i = 0; i < 16; i++) {
      m[i] = _load64(buffer, i * 8);
    }

    // Инициализация рабочего вектора v[0..15]
    for (var i = 0; i < 8; i++) {
      v[i] = _h[i]; // v[0..7] = h[0..7]
      v[i + 8] = _iv[i]; // v[8..15] = IV[0..7]
    }

    // v[12] ^= t[0] (младшие биты счетчика байтов)
    v[12] ^= _t[0];

    // v[13] ^= t[1] (старшие биты счетчика байтов)
    v[13] ^= _t[1];

    // Если это последний блок, инвертируем v[14]
    if (_f) {
      v[14] = ~v[14];
    }

    // Выполняем 12 раундов сжатия
    for (var r = 0; r < 12; r++) {
      // Column mixing
      _mixtwoRow(v, m, 0, 4, 8, 12, r, 0);
      _mixtwoRow(v, m, 1, 5, 9, 13, r, 1);
      _mixtwoRow(v, m, 2, 6, 10, 14, r, 2);
      _mixtwoRow(v, m, 3, 7, 11, 15, r, 3);

      // Diagonal mixing
      _mixtwoRow(v, m, 0, 5, 10, 15, r, 4);
      _mixtwoRow(v, m, 1, 6, 11, 12, r, 5);
      _mixtwoRow(v, m, 2, 7, 8, 13, r, 6);
      _mixtwoRow(v, m, 3, 4, 9, 14, r, 7);
    }

    // Финальное смешивание результата
    for (var i = 0; i < 8; i++) {
      _h[i] = _h[i] ^ v[i] ^ v[i + 8];
    }
  }

  /// Функция перемешивания G для BLAKE2b, точно соответствующая RFC 7693
  void _mixtwoRow(
      Uint64List v, Uint64List m, int a, int b, int c, int d, int r, int i) {
    final s = _sigma;

    // Строка r, столбцы 2*i и 2*i+1 из таблицы перестановок
    final mi = s[r % 10][2 * i];
    final mi1 = s[r % 10][2 * i + 1];

    // Точно следуем алгоритму из RFC 7693, раздел 3.1:
    // v[a] = (v[a] + v[b] + m[sigma[r][2*i]]) mod 2^64
    v[a] = _add64(v[a], _add64(v[b], m[mi]));

    // v[d] = ROTR_64(v[d] ^ v[a], 32)
    v[d] = _rotr64(v[d] ^ v[a], 32);

    // v[c] = (v[c] + v[d]) mod 2^64
    v[c] = _add64(v[c], v[d]);

    // v[b] = ROTR_64(v[b] ^ v[c], 24)
    v[b] = _rotr64(v[b] ^ v[c], 24);

    // v[a] = (v[a] + v[b] + m[sigma[r][2*i+1]]) mod 2^64
    v[a] = _add64(v[a], _add64(v[b], m[mi1]));

    // v[d] = ROTR_64(v[d] ^ v[a], 16)
    v[d] = _rotr64(v[d] ^ v[a], 16);

    // v[c] = (v[c] + v[d]) mod 2^64
    v[c] = _add64(v[c], v[d]);

    // v[b] = ROTR_64(v[b] ^ v[c], 63)
    v[b] = _rotr64(v[b] ^ v[c], 63);
  }

  /// Загружает 64-битное слово из буфера (little-endian)
  int _load64(Uint8List buf, int offset) {
    if (offset + 8 > buf.length) {
      // Если выходим за пределы буфера, обрабатываем доступные байты
      int result = 0;
      for (var i = 0; i < 8 && offset + i < buf.length; i++) {
        result |= (buf[offset + i] & 0xFF) << (8 * i);
      }
      return result;
    }

    // Стандартная обработка little-endian
    return (buf[offset] & 0xFF) |
        ((buf[offset + 1] & 0xFF) << 8) |
        ((buf[offset + 2] & 0xFF) << 16) |
        ((buf[offset + 3] & 0xFF) << 24) |
        ((buf[offset + 4] & 0xFF) << 32) |
        ((buf[offset + 5] & 0xFF) << 40) |
        ((buf[offset + 6] & 0xFF) << 48) |
        ((buf[offset + 7] & 0xFF) << 56);
  }

  /// Сложение по модулю 2^64
  int _add64(int a, int b) {
    return (a + b) & 0xFFFFFFFFFFFFFFFF;
  }

  /// Циклический сдвиг вправо для 64-битных значений
  int _rotr64(int x, int n) {
    return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF;
  }

  // Стандартный IV из спецификации BLAKE2b
  static final _iv = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
  ];

  /// Таблица перестановок SIGMA из RFC 7693
  static final _sigma = [
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
  ];

  /// Возвращает объект sigma для базового класса
  @override
  Uint8List get sigma => Uint8List.fromList(_sigma.expand((x) => x).toList());

  /// Returns a [Blake2b] instance using [Strings] for the
  /// [key], [salt], and [personalization] arguments.
  ///
  /// [key] may be null and can be any length.
  ///
  /// [salt] and [personalization] may be null and
  /// must both be 16 characters in length.
  static Blake2b fromStrings({
    int digestLength = 32,
    String? key,
    String? salt,
    String? personalization,
  }) {
    assert(digestLength > 0 && digestLength <= 64);
    assert(salt == null || salt.length == 16);
    assert(personalization == null || personalization.length == 16);

    return Blake2b(
      digestLength: digestLength,
      key: (key == null) ? null : Uint8List.fromList(key.codeUnits),
      salt: (salt == null) ? null : Uint8List.fromList(salt.codeUnits),
      personalization: (personalization != null)
          ? Uint8List.fromList(personalization.codeUnits)
          : null,
    );
  }
}
