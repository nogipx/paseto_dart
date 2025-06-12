import 'dart:typed_data';

import 'package:paseto_dart/blake2/ufixnum.dart';
import 'package:test/test.dart';

void main() {
  group('UFIXnum Comprehensive Tests', () {
    group('8-bit operations', () {
      test('clip8 обрезает до 8 бит', () {
        expect(clip8(0xFF), equals(0xFF));
        expect(clip8(0x100), equals(0x00)); // Переполнение
        expect(clip8(0x1FF), equals(0xFF));
        expect(clip8(0), equals(0));
        expect(clip8(-1), equals(0xFF)); // Отрицательные числа
      });

      test('sum8 и csum8 сложение 8-бит', () {
        expect(sum8(0x7F, 0x01), equals(0x80));
        expect(sum8(0xFF, 0x01), equals(0x00)); // Переполнение
        expect(sum8(0x80, 0x80), equals(0x00));
        expect(sum8(0, 0), equals(0));

        // csum8 с автоматическим клиппингом
        expect(csum8(0x100, 0x50), equals(0x50)); // clip8(0x100) = 0x00
        expect(csum8(0x1FF, 0x01), equals(0x00)); // clip8(0x1FF) = 0xFF
      });

      test('sub8 и csub8 вычитание 8-бит', () {
        expect(sub8(0x80, 0x01), equals(0x7F));
        expect(sub8(0x00, 0x01), equals(0xFF)); // Underflow
        expect(sub8(0xFF, 0xFF), equals(0x00));
        expect(sub8(0x50, 0x30), equals(0x20));

        // csub8 с автоматическим клиппингом
        expect(csub8(0x180, 0x01), equals(0x7F)); // clip8(0x180) = 0x80
      });

      test('shiftl8 и cshiftl8 левый сдвиг 8-бит', () {
        expect(shiftl8(0x01, 1), equals(0x02));
        expect(shiftl8(0x80, 1), equals(0x00)); // Переполнение
        expect(shiftl8(0x0F, 4), equals(0xF0));
        expect(shiftl8(0xFF, 8), equals(0xFF)); // n & 0x07 = 0
        expect(shiftl8(0x01, 9), equals(0x02)); // n & 0x07 = 1

        expect(cshiftl8(0x101, 1), equals(0x02)); // clip8(0x101) = 0x01
      });

      test('shiftr8 и cshiftr8 правый сдвиг 8-бит', () {
        expect(shiftr8(0x02, 1), equals(0x01));
        expect(shiftr8(0x80, 1), equals(0x40));
        expect(shiftr8(0xF0, 4), equals(0x0F));
        expect(shiftr8(0xFF, 8), equals(0xFF)); // n & 0x07 = 0
        expect(shiftr8(0x04, 9), equals(0x02)); // n & 0x07 = 1

        expect(cshiftr8(0x102, 1), equals(0x01)); // clip8(0x102) = 0x02
      });

      test('neg8 и cneg8 отрицание 8-бит', () {
        expect(neg8(0x01), equals(0xFF));
        expect(neg8(0xFF), equals(0x01));
        expect(neg8(0x00), equals(0x00));
        expect(neg8(0x80), equals(0x80)); // -128 в двухзначном дополнении

        expect(cneg8(0x101), equals(0xFF)); // clip8(0x101) = 0x01
      });

      test('not8 и cnot8 битовое НЕ 8-бит', () {
        expect(not8(0x00), equals(0xFF));
        expect(not8(0xFF), equals(0x00));
        expect(not8(0xF0), equals(0x0F));
        expect(not8(0x55), equals(0xAA)); // 01010101 -> 10101010

        expect(cnot8(0x155), equals(0xAA)); // clip8(0x155) = 0x55
      });

      test('rotl8 и crotl8 циклический левый сдвиг 8-бит', () {
        expect(rotl8(0x01, 1), equals(0x02));
        expect(rotl8(0x80, 1), equals(0x01)); // Бит переходит в начало
        expect(rotl8(0xF0, 4), equals(0x0F));
        expect(rotl8(0x12, 8), equals(0x12)); // Полный оборот
        expect(rotl8(0x12, 9), equals(0x24)); // 8 + 1

        expect(crotl8(0x181, 1), equals(0x03)); // clip8(0x181) = 0x81
      });

      test('rotr8 и crotr8 циклический правый сдвиг 8-бит', () {
        expect(rotr8(0x02, 1), equals(0x01));
        expect(rotr8(0x01, 1), equals(0x80)); // Бит переходит в конец
        expect(rotr8(0x0F, 4), equals(0xF0));
        expect(rotr8(0x12, 8), equals(0x12)); // Полный оборот
        expect(rotr8(0x12, 9), equals(0x09)); // 8 + 1

        expect(crotr8(0x102, 1), equals(0x01)); // clip8(0x102) = 0x02
      });
    });

    group('16-bit operations', () {
      test('clip16 обрезает до 16 бит', () {
        expect(clip16(0xFFFF), equals(0xFFFF));
        expect(clip16(0x10000), equals(0x0000)); // Переполнение
        expect(clip16(0x1FFFF), equals(0xFFFF));
        expect(clip16(0), equals(0));
        expect(clip16(-1), equals(0xFFFF));
      });

      test('pack16 и unpack16 упаковка/распаковка', () {
        final buffer = Uint8List(4);

        // Little endian
        pack16(0x1234, buffer, 0, Endian.little);
        expect(buffer[0], equals(0x34));
        expect(buffer[1], equals(0x12));
        expect(unpack16(buffer, 0, Endian.little), equals(0x1234));

        // Big endian
        pack16(0x5678, buffer, 2, Endian.big);
        expect(buffer[2], equals(0x56));
        expect(buffer[3], equals(0x78));
        expect(unpack16(buffer, 2, Endian.big), equals(0x5678));

        // Тест с ByteData
        final byteData = ByteData.view(buffer.buffer);
        pack16(0xABCD, byteData, 0, Endian.little);
        expect(unpack16(byteData, 0, Endian.little), equals(0xABCD));
      });

      test('pack16/unpack16 граничные случаи', () {
        final buffer = Uint8List(2);

        // Минимальное значение
        pack16(0x0000, buffer, 0, Endian.little);
        expect(unpack16(buffer, 0, Endian.little), equals(0x0000));

        // Максимальное значение
        pack16(0xFFFF, buffer, 0, Endian.big);
        expect(unpack16(buffer, 0, Endian.big), equals(0xFFFF));
      });
    });

    group('32-bit operations', () {
      test('clip32 обрезает до 32 бит', () {
        expect(clip32(0xFFFFFFFF), equals(0xFFFFFFFF));
        expect(clip32(0x100000000), equals(0x00000000)); // Переполнение
        expect(clip32(0x1FFFFFFFF), equals(0xFFFFFFFF));
        expect(clip32(0), equals(0));
      });

      test('sum32 и csum32 сложение 32-бит', () {
        expect(sum32(0x7FFFFFFF, 0x01), equals(0x80000000));
        expect(sum32(0xFFFFFFFF, 0x01), equals(0x00000000)); // Переполнение
        expect(sum32(0x80000000, 0x80000000), equals(0x00000000));
        expect(sum32(0x12345678, 0x87654321), equals(0x99999999));

        // csum32 с автоматическим клиппингом
        expect(csum32(0x100000000, 0x50), equals(0x50)); // clip32 = 0x00
      });

      test('sub32 и csub32 вычитание 32-бит', () {
        expect(sub32(0x80000000, 0x01), equals(0x7FFFFFFF));
        expect(sub32(0x00000000, 0x01), equals(0xFFFFFFFF)); // Underflow
        expect(sub32(0xFFFFFFFF, 0xFFFFFFFF), equals(0x00000000));
        expect(sub32(0x99999999, 0x12345678), equals(0x87654321));

        expect(csub32(0x180000000, 0x01), equals(0x7FFFFFFF));
      });

      test('shiftl32 и cshiftl32 левый сдвиг 32-бит', () {
        expect(shiftl32(0x00000001, 1), equals(0x00000002));
        expect(shiftl32(0x80000000, 1), equals(0x00000000)); // Переполнение
        expect(shiftl32(0x0000FFFF, 16), equals(0xFFFF0000));
        expect(shiftl32(0xFFFFFFFF, 32), equals(0xFFFFFFFF)); // n & 0x1F = 0
        expect(shiftl32(0x00000001, 33), equals(0x00000002)); // n & 0x1F = 1

        expect(cshiftl32(0x100000001, 1), equals(0x00000002));
      });

      test('shiftr32 и cshiftr32 правый сдвиг 32-бит', () {
        expect(shiftr32(0x00000002, 1), equals(0x00000001));
        expect(shiftr32(0x80000000, 1), equals(0x40000000));
        expect(shiftr32(0xFFFF0000, 16), equals(0x0000FFFF));
        expect(shiftr32(0xFFFFFFFF, 32), equals(0xFFFFFFFF)); // n & 0x1F = 0
        expect(shiftr32(0x00000004, 33), equals(0x00000002)); // n & 0x1F = 1

        expect(cshiftr32(0x100000002, 1), equals(0x00000001));
      });

      test('neg32 и cneg32 отрицание 32-бит', () {
        expect(neg32(0x00000001), equals(0xFFFFFFFF));
        expect(neg32(0xFFFFFFFF), equals(0x00000001));
        expect(neg32(0x00000000), equals(0x00000000));
        expect(neg32(0x80000000), equals(0x80000000));

        expect(cneg32(0x100000001), equals(0xFFFFFFFF));
      });

      test('not32 и cnot32 битовое НЕ 32-бит', () {
        expect(not32(0x00000000), equals(0xFFFFFFFF));
        expect(not32(0xFFFFFFFF), equals(0x00000000));
        expect(not32(0xFFFF0000), equals(0x0000FFFF));
        expect(not32(0x55555555), equals(0xAAAAAAAA));

        expect(cnot32(0x155555555), equals(0xAAAAAAAA));
      });

      test('rotl32 и crotl32 циклический левый сдвиг 32-бит', () {
        expect(rotl32(0x00000001, 1), equals(0x00000002));
        expect(rotl32(0x80000000, 1),
            equals(0x00000001)); // Бит переходит в начало
        expect(rotl32(0x12345678, 8), equals(0x34567812));
        expect(rotl32(0x12345678, 32), equals(0x12345678)); // Полный оборот
        expect(rotl32(0x12345678, 33), equals(0x2468ACF0)); // 32 + 1

        expect(crotl32(0x180000000, 1), equals(0x00000001));
      });

      test('rotr32 и crotr32 циклический правый сдвиг 32-бит', () {
        expect(rotr32(0x00000002, 1), equals(0x00000001));
        expect(
            rotr32(0x00000001, 1), equals(0x80000000)); // Бит переходит в конец
        expect(rotr32(0x12345678, 8), equals(0x78123456));
        expect(rotr32(0x12345678, 32), equals(0x12345678)); // Полный оборот
        expect(rotr32(0x12345678, 33), equals(0x091A2B3C)); // 32 + 1

        expect(crotr32(0x100000002, 1), equals(0x00000001));
      });
    });

    group('Edge cases и производительность', () {
      test('Операции с нулями', () {
        // 8-bit
        expect(sum8(0, 0), equals(0));
        expect(sub8(0, 0), equals(0));
        expect(shiftl8(0, 5), equals(0));
        expect(shiftr8(0, 5), equals(0));
        expect(neg8(0), equals(0));
        expect(not8(0), equals(0xFF));
        expect(rotl8(0, 3), equals(0));
        expect(rotr8(0, 3), equals(0));

        // 32-bit
        expect(sum32(0, 0), equals(0));
        expect(sub32(0, 0), equals(0));
        expect(shiftl32(0, 16), equals(0));
        expect(shiftr32(0, 16), equals(0));
        expect(neg32(0), equals(0));
        expect(not32(0), equals(0xFFFFFFFF));
        expect(rotl32(0, 10), equals(0));
        expect(rotr32(0, 10), equals(0));
      });

      test('Операции с максимальными значениями', () {
        // 8-bit максимум
        expect(sum8(0xFF, 0), equals(0xFF));
        expect(sub8(0xFF, 0), equals(0xFF));
        expect(shiftl8(0xFF, 0), equals(0xFF));
        expect(shiftr8(0xFF, 0), equals(0xFF));
        expect(not8(0xFF), equals(0));

        // 32-bit максимум
        expect(sum32(0xFFFFFFFF, 0), equals(0xFFFFFFFF));
        expect(sub32(0xFFFFFFFF, 0), equals(0xFFFFFFFF));
        expect(shiftl32(0xFFFFFFFF, 0), equals(0xFFFFFFFF));
        expect(shiftr32(0xFFFFFFFF, 0), equals(0xFFFFFFFF));
        expect(not32(0xFFFFFFFF), equals(0));
      });

      test('Большие сдвиги (проверка маскирования)', () {
        // 8-bit: n маскируется как n & 0x07
        expect(shiftl8(0x01, 8), equals(0x01)); // 8 & 7 = 0
        expect(shiftl8(0x01, 15), equals(0x80)); // 15 & 7 = 7
        expect(shiftr8(0x80, 16), equals(0x80)); // 16 & 7 = 0
        expect(rotl8(0x12, 24), equals(0x12)); // 24 & 7 = 0
        expect(rotr8(0x12, 31), equals(0x24)); // 31 & 7 = 7

        // 32-bit: n маскируется как n & 0x1F
        expect(shiftl32(0x00000001, 32), equals(0x00000001)); // 32 & 31 = 0
        expect(shiftl32(0x00000001, 63), equals(0x80000000)); // 63 & 31 = 31
        expect(shiftr32(0x80000000, 64), equals(0x80000000)); // 64 & 31 = 0
        expect(rotl32(0x12345678, 96), equals(0x12345678)); // 96 & 31 = 0
        expect(rotr32(0x12345678, 127), equals(0x2468ACF0)); // 127 & 31 = 31
      });

      test('Производительность с множественными операциями', () {
        // Имитируем интенсивные вычисления
        int result8 = 0x55;
        for (int i = 0; i < 1000; i++) {
          result8 = csum8(result8, i & 0xFF);
          result8 = crotl8(result8, 1);
          result8 = cnot8(result8);
        }
        expect(result8, isA<int>());
        expect(result8, lessThanOrEqualTo(0xFF));

        int result32 = 0x55555555;
        for (int i = 0; i < 100; i++) {
          result32 = csum32(result32, i);
          result32 = crotl32(result32, 1);
          result32 = cnot32(result32);
        }
        expect(result32, isA<int>());
        expect(result32, lessThanOrEqualTo(0xFFFFFFFF));
      });
    });
  });
}
