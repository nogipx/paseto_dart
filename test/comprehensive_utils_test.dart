import 'dart:convert';
import 'dart:typed_data';

import 'package:paseto_dart/paseto_dart.dart';
import 'package:paseto_dart/utils/pae.dart';
import 'package:paseto_dart/blake2/_index.dart' as blake2;
import 'package:test/test.dart';

void main() {
  group('Comprehensive Utils Tests', () {
    group('SafeBase64 Extended Tests', () {
      test('кодирование и декодирование стандартных данных', () {
        final testCases = [
          'Hello, World!',
          'PASETO токен тест',
          '{"key": "value", "number": 42}',
          'Special chars: !@#\$%^&*()_+-=[]{}|;:,.<>?',
          'Multi\nLine\nText',
          'Emoji: 🔐🚀✨',
        ];

        for (final testCase in testCases) {
          final bytes = utf8.encode(testCase);
          final encoded = SafeBase64.encode(bytes);
          final decoded = SafeBase64.decode(encoded);
          final result = utf8.decode(decoded);

          expect(result, equals(testCase));
          expect(decoded, equals(bytes));
        }
      });

      test('кодирование бинарных данных', () {
        final testCases = [
          Uint8List.fromList([]),
          Uint8List.fromList([0]),
          Uint8List.fromList([255]),
          Uint8List.fromList([0, 255, 128, 64]),
          Uint8List.fromList(List.generate(256, (i) => i)),
          Uint8List.fromList(List.generate(1000, (i) => i % 256)),
        ];

        for (final testCase in testCases) {
          final encoded = SafeBase64.encode(testCase);
          final decoded = SafeBase64.decode(encoded);

          expect(decoded, equals(testCase));
        }
      });

      test('валидация URL-safe base64', () {
        final encoded = SafeBase64.encode(utf8.encode('test?data+here'));

        // URL-safe base64 не должен содержать + или /
        expect(encoded, isNot(contains('+')));
        expect(encoded, isNot(contains('/')));

        // Должен корректно декодироваться
        final decoded = SafeBase64.decode(encoded);
        expect(utf8.decode(decoded), equals('test?data+here'));
      });

      test('большие данные', () {
        final largeData =
            Uint8List.fromList(List.generate(10000, (i) => i % 256));

        final encoded = SafeBase64.encode(largeData);
        final decoded = SafeBase64.decode(encoded);

        expect(decoded.length, equals(10000));
        expect(decoded, equals(largeData));
      });

      test('edge cases для base64', () {
        // Пустые данные
        expect(SafeBase64.encode(Uint8List(0)), equals(''));
        expect(SafeBase64.decode(''), isEmpty);

        // Один байт
        expect(SafeBase64.decode(SafeBase64.encode([42])), equals([42]));

        // Два байта
        expect(
            SafeBase64.decode(SafeBase64.encode([42, 84])), equals([42, 84]));

        // Три байта
        expect(SafeBase64.decode(SafeBase64.encode([42, 84, 126])),
            equals([42, 84, 126]));
      });

      test('совместимость с стандартным base64', () {
        final testData = utf8.encode('Test данные for base64 compatibility');

        // Кодируем нашим SafeBase64
        final safeEncoded = SafeBase64.encode(testData);

        // Декодируем стандартным Dart base64 (с заменой символов)
        final standardCompatible =
            safeEncoded.replaceAll('-', '+').replaceAll('_', '/');

        // Добавляем padding если нужно
        final padding = '=' * ((4 - standardCompatible.length % 4) % 4);
        final withPadding = standardCompatible + padding;

        final standardDecoded = base64.decode(withPadding);

        expect(standardDecoded, equals(testData));
      });

      test('некорректный base64 input', () {
        expect(() => SafeBase64.decode('invalid!@#'),
            throwsA(isA<FormatException>()));
        expect(() => SafeBase64.decode('тест'), throwsA(isA<Exception>()));
      });
    });

    group('PAE (Pre-Authentication Encoding) Tests', () {
      test('PAE с пустым списком', () {
        final result = pae([]);

        expect(
            result, equals([0, 0, 0, 0, 0, 0, 0, 0])); // 64-bit little-endian 0
      });

      test('PAE с одним элементом', () {
        final data = utf8.encode('test');
        final result = pae([data]);

        // Ожидаем: count(1) + length(4) + data('test')
        final expected = [
          1, 0, 0, 0, 0, 0, 0, 0, // count = 1 (64-bit LE)
          4, 0, 0, 0, 0, 0, 0, 0, // length = 4 (64-bit LE)
          ...data, // 'test'
        ];

        expect(result, equals(expected));
      });

      test('PAE с несколькими элементами', () {
        final data1 = utf8.encode('hello');
        final data2 = utf8.encode('world');
        final result = pae([data1, data2]);

        final expected = [
          2, 0, 0, 0, 0, 0, 0, 0, // count = 2
          5, 0, 0, 0, 0, 0, 0, 0, // length1 = 5
          ...data1, // 'hello'
          5, 0, 0, 0, 0, 0, 0, 0, // length2 = 5
          ...data2, // 'world'
        ];

        expect(result, equals(expected));
      });

      test('PAE с пустыми элементами', () {
        final empty1 = Uint8List(0);
        final empty2 = Uint8List(0);
        final result = pae([empty1, empty2]);

        final expected = [
          2, 0, 0, 0, 0, 0, 0, 0, // count = 2
          0, 0, 0, 0, 0, 0, 0, 0, // length1 = 0
          0, 0, 0, 0, 0, 0, 0, 0, // length2 = 0
        ];

        expect(result, equals(expected));
      });

      test('PAE с большими данными', () {
        final largeData =
            Uint8List.fromList(List.generate(1000, (i) => i % 256));
        final result = pae([largeData]);

        // Проверяем заголовок
        expect(result.sublist(0, 8),
            equals([1, 0, 0, 0, 0, 0, 0, 0])); // count = 1
        expect(result.sublist(8, 16),
            equals([232, 3, 0, 0, 0, 0, 0, 0])); // length = 1000 (LE)

        // Проверяем данные
        expect(result.sublist(16), equals(largeData));
        expect(result.length, equals(16 + 1000));
      });

      test('PAE с различными типами данных', () {
        final testCases = [
          utf8.encode('text'),
          Uint8List.fromList([0, 255, 128]),
          utf8.encode('{"json": true}'),
          Uint8List.fromList(List.generate(100, (i) => i)),
        ];

        final result = pae(testCases);

        // Проверяем count
        expect(result.sublist(0, 8), equals([4, 0, 0, 0, 0, 0, 0, 0]));

        int offset = 8;
        for (int i = 0; i < testCases.length; i++) {
          final expectedLength = testCases[i].length;

          // Проверяем length
          final lengthBytes = _int64ToLittleEndian(expectedLength);
          expect(result.sublist(offset, offset + 8), equals(lengthBytes));
          offset += 8;

          // Проверяем данные
          expect(result.sublist(offset, offset + expectedLength),
              equals(testCases[i]));
          offset += expectedLength;
        }

        expect(result.length, equals(offset));
      });

      test('PAE детерминистичность', () {
        final data1 = utf8.encode('test1');
        final data2 = utf8.encode('test2');

        final result1 = pae([data1, data2]);
        final result2 = pae([data1, data2]);
        final result3 = pae([data2, data1]); // Другой порядок

        expect(result1, equals(result2));
        expect(result1, isNot(equals(result3)));
      });

      test('PAE большое количество элементов', () {
        final elements = List.generate(100, (i) => utf8.encode('item$i'));
        final result = pae(elements);

        // Проверяем count
        expect(result.sublist(0, 8), equals([100, 0, 0, 0, 0, 0, 0, 0]));

        int offset = 8;
        for (int i = 0; i < elements.length; i++) {
          final length = elements[i].length;

          // Проверяем длину
          final lengthBytes = _int64ToLittleEndian(length);
          expect(result.sublist(offset, offset + 8), equals(lengthBytes));
          offset += 8;

          // Проверяем данные
          expect(result.sublist(offset, offset + length), equals(elements[i]));
          offset += length;
        }
      });

      test('PAE с бинарными данными и нулевыми байтами', () {
        final binaryData = Uint8List.fromList([0, 1, 0, 255, 0, 128, 0]);
        final textData = utf8.encode('text\x00with\x00nulls');

        final result = pae([binaryData, textData]);

        expect(result.sublist(0, 8), equals([2, 0, 0, 0, 0, 0, 0, 0])); // count

        // Первый элемент
        expect(
            result.sublist(8, 16), equals([7, 0, 0, 0, 0, 0, 0, 0])); // length
        expect(result.sublist(16, 23), equals(binaryData));

        // Второй элемент
        expect(result.sublist(23, 31),
            equals([15, 0, 0, 0, 0, 0, 0, 0])); // length
        expect(result.sublist(31), equals(textData));
      });
    });

    group('Byte Utils Tests', () {
      test('bytesToHex конверсия', () {
        final testCases = [
          {'bytes': <int>[], 'hex': ''},
          {
            'bytes': [0],
            'hex': '00'
          },
          {
            'bytes': [255],
            'hex': 'ff'
          },
          {
            'bytes': [0, 255, 128],
            'hex': '00ff80'
          },
          {
            'bytes': [0x12, 0x34, 0xAB, 0xCD],
            'hex': '1234abcd'
          },
        ];

        for (final testCase in testCases) {
          final bytes = testCase['bytes'] as List<int>;
          final expectedHex = testCase['hex'] as String;

          final result = blake2.ByteUtils.bytesToHex(bytes);
          expect(result.toLowerCase(), equals(expectedHex));
        }
      });

      test('hexToBytes конверсия', () {
        final testCases = [
          {'hex': '', 'bytes': <int>[]},
          {
            'hex': '00',
            'bytes': [0]
          },
          {
            'hex': 'FF',
            'bytes': [255]
          },
          {
            'hex': '00ff80',
            'bytes': [0, 255, 128]
          },
          {
            'hex': '1234ABCD',
            'bytes': [0x12, 0x34, 0xAB, 0xCD]
          },
          {
            'hex': '1234abcd',
            'bytes': [0x12, 0x34, 0xAB, 0xCD]
          }, // lowercase
          {
            'hex': '12 34 AB CD',
            'bytes': [0x12, 0x34, 0xAB, 0xCD]
          }, // with spaces
        ];

        for (final testCase in testCases) {
          final hex = testCase['hex'] as String;
          final expectedBytes = testCase['bytes'] as List<int>;

          final result = blake2.ByteUtils.hexToBytes(hex);
          expect(result, equals(expectedBytes));
        }
      });

      test('hex round trip', () {
        final testBytes = List.generate(256, (i) => i);

        final hex = blake2.ByteUtils.bytesToHex(testBytes);
        final restored = blake2.ByteUtils.hexToBytes(hex);

        expect(restored, equals(testBytes));
      });

      test('некорректный hex input', () {
        expect(() => blake2.ByteUtils.hexToBytes('ZZ'),
            throwsA(isA<FormatException>()));
        expect(() => blake2.ByteUtils.hexToBytes('123'),
            throwsA(isA<ArgumentError>())); // odd length
        expect(() => blake2.ByteUtils.hexToBytes('12GH'),
            throwsA(isA<FormatException>()));
      });

      test('stringToBytes и bytesToString', () {
        final testStrings = [
          '',
          'hello',
          'Hello, мир! 🌍',
          'ASCII only',
          'Тест unicode: éñ中文',
          '{"json": true, "array": [1,2,3]}',
        ];

        for (final str in testStrings) {
          final bytes = blake2.ByteUtils.stringToBytes(str);
          final restored = blake2.ByteUtils.bytesToString(bytes);
          expect(restored, equals(str));
        }
      });

      test('xor операция', () {
        final a = [0x12, 0x34, 0x56, 0x78];
        final b = [0x9A, 0xBC, 0xDE, 0xF0];
        final expected = [0x88, 0x88, 0x88, 0x88]; // 12^9A = 88, etc.

        final result = blake2.ByteUtils.xor(a, b);
        expect(result, equals(expected));

        // XOR с самим собой должно давать нули
        final zeros = blake2.ByteUtils.xor(a, a);
        expect(zeros, equals([0, 0, 0, 0]));
      });

      test('xor с разными длинами массивов', () {
        final a = [1, 2, 3];
        final b = [4, 5];

        expect(() => blake2.ByteUtils.xor(a, b), throwsA(isA<ArgumentError>()));
      });

      test('le64 конверсия', () {
        final testCases = [
          {
            'value': 0,
            'expected': [0, 0, 0, 0, 0, 0, 0, 0]
          },
          {
            'value': 1,
            'expected': [1, 0, 0, 0, 0, 0, 0, 0]
          },
          {
            'value': 0x0102030405060708,
            'expected': [8, 7, 6, 5, 4, 3, 2, 1]
          },
          {
            'value': 0xFF,
            'expected': [255, 0, 0, 0, 0, 0, 0, 0]
          },
          {
            'value': 0xFFFFFFFFFFFFFFFF,
            'expected': [255, 255, 255, 255, 255, 255, 255, 255]
          },
        ];

        for (final testCase in testCases) {
          final value = testCase['value'] as int;
          final expected = testCase['expected'] as List<int>;

          final result = blake2.ByteUtils.le64(value);
          expect(result, equals(expected));
        }
      });

      test('constantTimeEquals сравнение', () {
        final a = [1, 2, 3, 4];
        final b = [1, 2, 3, 4];
        final c = [1, 2, 3, 5];
        final d = [1, 2, 3];

        expect(blake2.ByteUtils.constantTimeEquals(a, b), isTrue);
        expect(blake2.ByteUtils.constantTimeEquals(a, c), isFalse);
        expect(blake2.ByteUtils.constantTimeEquals(a, d), isFalse);

        // Пустые массивы
        expect(blake2.ByteUtils.constantTimeEquals([], []), isTrue);

        // Большие массивы
        final large1 = List.generate(1000, (i) => i % 256);
        final large2 = List.generate(1000, (i) => i % 256);
        final large3 = List.generate(1000, (i) => (i + 1) % 256);

        expect(blake2.ByteUtils.constantTimeEquals(large1, large2), isTrue);
        expect(blake2.ByteUtils.constantTimeEquals(large1, large3), isFalse);
      });

      test('большие данные hex конверсия', () {
        final largeBytes = List.generate(10000, (i) => i % 256);

        final hex = blake2.ByteUtils.bytesToHex(largeBytes);
        final restored = blake2.ByteUtils.hexToBytes(hex);

        expect(restored, equals(largeBytes));
        expect(hex.length, equals(20000)); // 2 символа на байт
      });
    });

    group('Utils Integration Tests', () {
      test('PAE + Base64 round trip', () {
        final elements = [
          utf8.encode('header'),
          utf8.encode('payload'),
          utf8.encode('footer'),
        ];

        final paeResult = pae(elements);
        final encoded = SafeBase64.encode(paeResult);
        final decoded = SafeBase64.decode(encoded);

        expect(decoded, equals(paeResult));
      });

      test('совместимость с PASETO specification', () {
        // Тест из официальной спецификации PASETO
        final h = utf8.encode('v4.local.');
        final n = Uint8List.fromList(List.generate(32, (i) => 0));
        final c = utf8.encode('test');
        final f = utf8.encode('');
        final i = utf8.encode('');

        final result = pae([h, n, c, f, i]);

        // Проверяем структуру
        expect(result.sublist(0, 8),
            equals([5, 0, 0, 0, 0, 0, 0, 0])); // count = 5

        int offset = 8;
        final elements = [h, n, c, f, i];

        for (final element in elements) {
          final length = element.length;
          final lengthBytes = _int64ToLittleEndian(length);

          expect(result.sublist(offset, offset + 8), equals(lengthBytes));
          offset += 8;

          expect(result.sublist(offset, offset + length), equals(element));
          offset += length;
        }
      });
    });
  });
}

// Вспомогательная функция для конвертации int в little-endian bytes
List<int> _int64ToLittleEndian(int value) {
  return [
    value & 0xff,
    (value >> 8) & 0xff,
    (value >> 16) & 0xff,
    (value >> 24) & 0xff,
    (value >> 32) & 0xff,
    (value >> 40) & 0xff,
    (value >> 48) & 0xff,
    (value >> 56) & 0xff,
  ];
}
