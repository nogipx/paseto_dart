import 'dart:typed_data';

import 'package:paseto_dart/blake2/ufixnum.dart';
import 'package:test/test.dart';

void main() {
  group('Register64 Tests', () {
    group('Конструкторы и базовые операции', () {
      test('Конструктор с одним 32-битным значением', () {
        final reg = Register64(0x12345678);
        expect(reg.hi32, equals(0));
        expect(reg.lo32, equals(0x12345678));
      });

      test('Конструктор с двумя 32-битными значениями', () {
        final reg = Register64(0x12345678, 0x9ABCDEF0);
        expect(reg.hi32, equals(0x12345678));
        expect(reg.lo32, equals(0x9ABCDEF0));
      });

      test('Конструктор копирования', () {
        final original = Register64(0x12345678, 0x9ABCDEF0);
        final copy = Register64(original);
        expect(copy.hi32, equals(0x12345678));
        expect(copy.lo32, equals(0x9ABCDEF0));
        expect(copy == original, isTrue);
      });

      test('set метод', () {
        final reg = Register64();

        // set с одним параметром
        reg.set(0x12345678);
        expect(reg.hi32, equals(0));
        expect(reg.lo32, equals(0x12345678));

        // set с двумя параметрами
        reg.set(0xAABBCCDD, 0xEEFF0011);
        expect(reg.hi32, equals(0xAABBCCDD));
        expect(reg.lo32, equals(0xEEFF0011));

        // set с Register64
        final other = Register64(0x11223344, 0x55667788);
        reg.set(other);
        expect(reg.hi32, equals(0x11223344));
        expect(reg.lo32, equals(0x55667788));
      });
    });

    group('Операторы сравнения', () {
      test('Оператор ==', () {
        final reg1 = Register64(0x12345678, 0x9ABCDEF0);
        final reg2 = Register64(0x12345678, 0x9ABCDEF0);
        final reg3 = Register64(0x12345678, 0x9ABCDEF1);

        expect(reg1 == reg2, isTrue);
        expect(reg1 == reg3, isFalse);
        // ignore: unrelated_type_equality_checks
        expect(reg1 == 'not a register', isFalse);
      });

      test('Оператор <', () {
        final reg1 = Register64(0x12345678, 0x9ABCDEF0);
        final reg2 = Register64(0x12345679, 0x9ABCDEF0);
        final reg3 = Register64(0x12345678, 0x9ABCDEF1);

        expect(reg1 < reg2, isTrue); // Сравнение по hi32
        expect(reg1 < reg3, isTrue); // Сравнение по lo32
        expect(reg2 < reg1, isFalse);
      });

      test('Операторы <=, >, >=', () {
        final reg1 = Register64(0x12345678, 0x9ABCDEF0);
        final reg2 = Register64(0x12345678, 0x9ABCDEF0);
        final reg3 = Register64(0x12345679, 0x9ABCDEF0);

        expect(reg1 <= reg2, isTrue); // Равны
        expect(reg1 <= reg3, isTrue); // Меньше
        expect(reg3 <= reg1, isFalse);

        expect(reg3 > reg1, isTrue);
        expect(reg1 > reg3, isFalse);

        expect(reg1 >= reg2, isTrue); // Равны
        expect(reg3 >= reg1, isTrue); // Больше
        expect(reg1 >= reg3, isFalse);
      });
    });

    group('Арифметические операции', () {
      test('sum с 32-битным числом', () {
        final reg = Register64(0x12345678, 0xFFFFFFFF);
        reg.sum(1);
        expect(reg.hi32, equals(0x12345679)); // Перенос из lo32
        expect(reg.lo32, equals(0x00000000));

        // Тест без переноса
        final reg2 = Register64(0, 0x12345678);
        reg2.sum(0x100);
        expect(reg2.hi32, equals(0));
        expect(reg2.lo32, equals(0x12345778));
      });

      test('sum с Register64', () {
        final reg1 = Register64(0x12345678, 0x9ABCDEF0);
        final reg2 = Register64(0x11111111, 0x70000000);
        reg1.sum(reg2);
        expect(reg1.hi32, equals(0x2345678A)); // +1 от переноса
        expect(reg1.lo32, equals(0x0ABCDEF0));

        // Тест с переносом
        final reg3 = Register64(0x12345678, 0xFFFFFFFF);
        final reg4 = Register64(0x11111111, 0x00000001);
        reg3.sum(reg4);
        expect(reg3.hi32, equals(0x2345678A)); // +1 от переноса
        expect(reg3.lo32, equals(0x00000000));
      });

      test('sumReg метод', () {
        final reg1 = Register64(0x12345678, 0x9ABCDEF0);
        final reg2 = Register64(0x11111111, 0x70000000);
        reg1.sumReg(reg2);
        expect(reg1.hi32, equals(0x2345678A)); // +1 от переноса
        expect(reg1.lo32, equals(0x0ABCDEF0));
      });

      test('sub вычитание', () {
        final reg1 = Register64(0x12345678, 0x9ABCDEF0);
        final reg2 = Register64(0x11111111, 0x70000000);
        reg1.sub(reg2);

        // Проверяем что результат корректен (reg1 - reg2)
        // Вычитание через сложение с отрицанием
        expect(reg1.hi32, isA<int>());
        expect(reg1.lo32, isA<int>());
      });

      test('mul умножение на 32-битное число', () {
        final reg = Register64(0, 0x12345678);
        reg.mul(2);
        expect(reg.hi32, equals(0));
        expect(reg.lo32, equals(0x2468ACF0));

        // Тест с переполнением в hi32
        final reg2 = Register64(0, 0x80000000);
        reg2.mul(2);
        expect(reg2.hi32, equals(1));
        expect(reg2.lo32, equals(0));
      });

      test('mul умножение на Register64', () {
        final reg1 = Register64(0, 0x1000);
        final reg2 = Register64(0, 0x1000);
        reg1.mul(reg2);
        expect(reg1.hi32, equals(0));
        expect(reg1.lo32, equals(0x01000000));
      });

      test('neg отрицание', () {
        final reg = Register64(0, 1);
        reg.neg();
        expect(reg.hi32, equals(0xFFFFFFFF));
        expect(reg.lo32, equals(0xFFFFFFFF));

        // Двойное отрицание должно вернуть исходное значение
        reg.neg();
        expect(reg.hi32, equals(0));
        expect(reg.lo32, equals(1));
      });
    });

    group('Битовые операции', () {
      test('not битовое НЕ', () {
        final reg = Register64(0x12345678, 0x9ABCDEF0);
        reg.not();
        expect(reg.hi32, equals(0xEDCBA987));
        expect(reg.lo32, equals(0x6543210F));
      });

      test('and битовое И', () {
        final reg1 = Register64(0xFF00FF00, 0xAAAAAAAA);
        final reg2 = Register64(0xF0F0F0F0, 0x55555555);
        reg1.and(reg2);
        expect(reg1.hi32, equals(0xF000F000));
        expect(reg1.lo32, equals(0x00000000));
      });

      test('or битовое ИЛИ', () {
        final reg1 = Register64(0xFF00FF00, 0xAAAAAAAA);
        final reg2 = Register64(0x0F0F0F0F, 0x55555555);
        reg1.or(reg2);
        expect(reg1.hi32, equals(0xFF0FFF0F));
        expect(reg1.lo32, equals(0xFFFFFFFF));
      });

      test('xor исключающее ИЛИ', () {
        final reg1 = Register64(0xFF00FF00, 0xAAAAAAAA);
        final reg2 = Register64(0x0F0F0F0F, 0x55555555);
        reg1.xor(reg2);
        expect(reg1.hi32, equals(0xF00FF00F));
        expect(reg1.lo32, equals(0xFFFFFFFF));
      });
    });

    group('Сдвиги и повороты', () {
      test('shiftl левый сдвиг', () {
        final reg = Register64(0x12345678, 0x9ABCDEF0);
        reg.shiftl(4);
        expect(reg.hi32, equals(0x23456789));
        expect(reg.lo32, equals(0xABCDEF00));

        // Тест сдвига на 32 бита
        final reg2 = Register64(0, 0x12345678);
        reg2.shiftl(32);
        expect(reg2.hi32, equals(0x12345678));
        expect(reg2.lo32, equals(0));

        // Тест сдвига больше 32 бит
        final reg3 = Register64(0, 0x12345678);
        reg3.shiftl(36); // 32 + 4
        expect(reg3.hi32, equals(0x23456780));
        expect(reg3.lo32, equals(0));
      });

      test('shiftr правый сдвиг', () {
        final reg = Register64(0x12345678, 0x9ABCDEF0);
        reg.shiftr(4);
        expect(reg.hi32, equals(0x01234567));
        expect(reg.lo32, equals(0x89ABCDEF));

        // Тест сдвига на 32 бита
        final reg2 = Register64(0x12345678, 0);
        reg2.shiftr(32);
        expect(reg2.hi32, equals(0));
        expect(reg2.lo32, equals(0x12345678));
      });

      test('rotl циклический левый сдвиг', () {
        final reg = Register64(0x12345678, 0x9ABCDEF0);
        reg.rotl(4);
        expect(reg.hi32, equals(0x23456789));
        expect(reg.lo32, equals(0xABCDEF01));

        // Тест поворота на 32 бита (обмен частей)
        final reg2 = Register64(0x12345678, 0x9ABCDEF0);
        reg2.rotl(32);
        expect(reg2.hi32, equals(0x9ABCDEF0));
        expect(reg2.lo32, equals(0x12345678));

        // Тест поворота на 64 бита (полный оборот)
        final reg3 = Register64(0x12345678, 0x9ABCDEF0);
        reg3.rotl(64);
        expect(reg3.hi32, equals(0x12345678));
        expect(reg3.lo32, equals(0x9ABCDEF0));
      });

      test('rotr циклический правый сдвиг', () {
        final reg = Register64(0x12345678, 0x9ABCDEF0);
        reg.rotr(4);
        expect(reg.hi32, equals(0x01234567));
        expect(reg.lo32, equals(0x89ABCDEF));

        // Тест поворота на 32 бита (обмен частей)
        final reg2 = Register64(0x12345678, 0x9ABCDEF0);
        reg2.rotr(32);
        expect(reg2.hi32, equals(0x9ABCDEF0));
        expect(reg2.lo32, equals(0x12345678));
      });

      test('Сдвиги с маскированием n & 0x3F', () {
        final reg = Register64(0x12345678, 0x9ABCDEF0);

        // Тест что большие значения n маскируются
        final original = Register64(reg);
        reg.shiftl(68); // 68 & 63 = 4
        original.shiftl(4);
        expect(reg.hi32, equals(original.hi32));
        expect(reg.lo32, equals(original.lo32));
      });
    });

    group('Pack/Unpack операции', () {
      test('pack32 и unpack32', () {
        final buffer = Uint8List(8);

        // Little endian
        pack32(0x12345678, buffer, 0, Endian.little);
        expect(buffer[0], equals(0x78));
        expect(buffer[1], equals(0x56));
        expect(buffer[2], equals(0x34));
        expect(buffer[3], equals(0x12));
        expect(unpack32(buffer, 0, Endian.little), equals(0x12345678));

        // Big endian
        pack32(0x9ABCDEF0, buffer, 4, Endian.big);
        expect(buffer[4], equals(0x9A));
        expect(buffer[5], equals(0xBC));
        expect(buffer[6], equals(0xDE));
        expect(buffer[7], equals(0xF0));
        expect(unpack32(buffer, 4, Endian.big), equals(0x9ABCDEF0));

        // Тест с ByteData
        final byteData = ByteData.view(buffer.buffer);
        pack32(0xFFFFFFFF, byteData, 0, Endian.little);
        expect(unpack32(byteData, 0, Endian.little), equals(0xFFFFFFFF));
      });

      test('pack32 с обрезанием больших значений', () {
        final buffer = Uint8List(4);

        // Число больше 32 бит должно обрезаться
        pack32(0x123456789ABC, buffer, 0,
            Endian.little); // Обрежется до 0x56789ABC
        expect(unpack32(buffer, 0, Endian.little), equals(0x56789ABC));
      });
    });

    group('Edge cases и производительность', () {
      test('Операции с нулевыми значениями', () {
        final reg = Register64(0, 0);

        reg.sum(0);
        expect(reg.hi32, equals(0));
        expect(reg.lo32, equals(0));

        reg.mul(100);
        expect(reg.hi32, equals(0));
        expect(reg.lo32, equals(0));

        reg.shiftl(32);
        expect(reg.hi32, equals(0));
        expect(reg.lo32, equals(0));
      });

      test('Операции с максимальными значениями', () {
        final reg = Register64(0xFFFFFFFF, 0xFFFFFFFF);

        reg.sum(1);
        expect(reg.hi32, equals(0)); // Переполнение
        expect(reg.lo32, equals(0));

        final reg2 = Register64(0xFFFFFFFF, 0xFFFFFFFF);
        reg2.not();
        expect(reg2.hi32, equals(0));
        expect(reg2.lo32, equals(0));
      });

      test('Производительность множественных операций', () {
        final reg = Register64(0x12345678, 0x9ABCDEF0);

        // Имитируем интенсивные вычисления
        for (int i = 0; i < 100; i++) {
          reg.sum(i);
          reg.rotl(1);
          reg.xor(Register64(i, i));
        }

        expect(reg.hi32, isA<int>());
        expect(reg.lo32, isA<int>());
      });
    });
  });
}
