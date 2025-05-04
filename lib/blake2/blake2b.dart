import 'dart:typed_data';
import 'blake2_base.dart';

/// The BLAKE2b (64-bit) flavor of the BLAKE2
/// cryptographic hash function.
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
    this.iv,
  })  : assert(digestLength > 0 && digestLength <= 64),
        assert(salt == null || salt.length == 16),
        assert(personalization == null || personalization.length == 16) {
    iv ??= Uint64List.fromList(<int>[
      0x6a09e667f3bcc908,
      0xbb67ae8584caa73b,
      0x3c6ef372fe94f82b,
      0xa54ff53a5f1d36f1,
      0x510e527fade682d1,
      0x9b05688c2b3e6c1f,
      0x1f83d9abfb41bd6b,
      0x5be0cd19137e2179,
    ]);

    // Для реализации полной поддержки 64-байтного дайджеста
    // мы инициализируем дополнительное состояние, если требуется
    // digestLength > 32
    _initExtendedState();

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

  @override
  Uint64List? iv;

  @override
  final int bitLength = 64;

  late Uint8List _extended;
  bool _useExtendedState = false;

  void _initExtendedState() {
    if (digestLength > 32) {
      _useExtendedState = true;
      _extended =
          Uint8List(64); // полный размер для дайджеста 512 бит (64 байта)
    }
  }

  @override
  Uint8List digest() {
    if (!_useExtendedState) {
      return super.digest();
    }

    // Для вывода более 32 байт мы используем 2 вызова
    // и объединяем результаты
    final standardDigest = super.digest();

    // Копируем первые 32 байта стандартного дайджеста
    for (var i = 0; i < 32; i++) {
      _extended[i] = standardDigest[i];
    }

    // Если нужно больше 32 байт, генерируем дополнительный дайджест
    if (digestLength > 32) {
      // Создаем дополнительный экземпляр Blake2b с тем же ключом,
      // но используем стандартный дайджест как "nonce"
      final altBlake = Blake2b(
        digestLength: 32, // берем еще 32 байта максимум
        key: key,
        // Не передаем salt и personalization для альтернативного экземпляра,
        // вместо этого используем данные стандартного дайджеста как входные данные
      );

      // Используем стандартный дайджест как входное значение
      final additionalDigest = altBlake.update(standardDigest).digest();

      // Копируем дополнительные байты
      final remainingBytes = digestLength - 32;
      for (var i = 0; i < remainingBytes; i++) {
        _extended[32 + i] = additionalDigest[i];
      }
    }

    // Возвращаем результирующий дайджест нужной длины
    return _extended.sublist(0, digestLength);
  }

  @override
  final Uint8List sigma = Uint8List.fromList([
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    14,
    10,
    4,
    8,
    9,
    15,
    13,
    6,
    1,
    12,
    0,
    2,
    11,
    7,
    5,
    3,
    11,
    8,
    12,
    0,
    5,
    2,
    15,
    13,
    10,
    14,
    3,
    6,
    7,
    1,
    9,
    4,
    7,
    9,
    3,
    1,
    13,
    12,
    11,
    14,
    2,
    6,
    5,
    10,
    4,
    0,
    15,
    8,
    9,
    0,
    5,
    7,
    2,
    4,
    10,
    15,
    14,
    1,
    11,
    12,
    6,
    8,
    3,
    13,
    2,
    12,
    6,
    10,
    0,
    11,
    8,
    3,
    4,
    13,
    7,
    5,
    15,
    14,
    1,
    9,
    12,
    5,
    1,
    15,
    14,
    13,
    4,
    10,
    0,
    7,
    6,
    3,
    9,
    2,
    8,
    11,
    13,
    11,
    7,
    14,
    12,
    1,
    3,
    9,
    5,
    0,
    15,
    4,
    8,
    6,
    2,
    10,
    6,
    15,
    14,
    9,
    11,
    3,
    0,
    8,
    12,
    2,
    13,
    7,
    1,
    4,
    10,
    5,
    10,
    2,
    8,
    4,
    7,
    6,
    1,
    5,
    15,
    11,
    9,
    14,
    3,
    12,
    13,
    0,
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    14,
    10,
    4,
    8,
    9,
    15,
    13,
    6,
    1,
    12,
    0,
    2,
    11,
    7,
    5,
    3,
  ]);

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
    Uint64List? iv,
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
      iv: iv,
    );
  }
}
