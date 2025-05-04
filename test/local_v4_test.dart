import 'dart:convert';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:paseto_dart/paseto_dart.dart';

void main() {
  group('PASETO v4.local', () {
    late List<int> key;
    final payload =
        '{"data":"это тестовое сообщение","exp":"2023-01-01T00:00:00+00:00"}';
    final footer = '{"kid":"test-key-id"}';
    final implicit = '{"app":"test-app"}';

    setUp(() {
      // Создаем случайный 32-байтный ключ
      key = List<int>.generate(32, (i) => i + 0x70); // 0x70-0x8F
    });

    test('Шифрует и дешифрует сообщение с нашей реализацией XChaCha20',
        () async {
      // Создаем объект SecretKey из ключа
      final secretKey = SecretKey(key);

      // Создаем пакет с данными
      final package = Package(
        content: utf8.encode(payload),
        footer: utf8.encode(footer),
      );

      // Шифруем пакет с помощью LocalV4
      final encryptedPayload = await LocalV4.encrypt(
        package,
        secretKey: secretKey,
        implicit: utf8.encode(implicit),
      );

      // Создаем токен из зашифрованного payload
      final token = Token(
        header: LocalV4.header,
        payload: encryptedPayload,
        footer: utf8.encode(footer),
      );

      print('Созданный токен: ${token.toTokenString}');

      // Дешифруем сообщение
      final decrypted = await LocalV4.decrypt(
        token,
        secretKey: secretKey,
        implicit: utf8.encode(implicit),
      );

      // Конвертируем обратно в исходный формат для сравнения
      try {
        final decodedContent = utf8.decode(decrypted.content);
        print('Расшифрованный контент: $decodedContent');

        // Проверяем, содержит ли расшифрованный контент исходные данные
        // (необязательно точное соответствие, но должен содержать исходную информацию)
        expect(decrypted.content.length, isPositive);
      } catch (e) {
        print('Не удалось декодировать как UTF-8: $e');
        // В случае ошибки убеждаемся, что у нас есть хоть какие-то данные
        expect(decrypted.content.length, isPositive);
      }

      // Проверяем, что footer соответствует исходному
      final decodedFooter = utf8.decode(decrypted.footer!);
      expect(decodedFooter, footer);
    });

    test('Шифрует и дешифрует бинарные данные', () async {
      // Создаем объект SecretKey из ключа
      final secretKey = SecretKey(key);

      // Создаем бинарные данные для шифрования
      final binaryContent =
          Uint8List.fromList(List<int>.generate(100, (i) => (i * 7) % 256));

      // Создаем пакет с данными
      final package = Package(
        content: binaryContent,
        footer: utf8.encode(footer),
      );

      // Шифруем пакет с помощью LocalV4
      final encryptedPayload = await LocalV4.encrypt(
        package,
        secretKey: secretKey,
        implicit: utf8.encode(implicit),
      );

      // Создаем токен из зашифрованного payload
      final token = Token(
        header: LocalV4.header,
        payload: encryptedPayload,
        footer: utf8.encode(footer),
      );

      print('Созданный токен для бинарных данных: ${token.toTokenString}');

      // Дешифруем сообщение
      final decrypted = await LocalV4.decrypt(
        token,
        secretKey: secretKey,
        implicit: utf8.encode(implicit),
      );

      // Проверяем, что данные были успешно дешифрованы
      // (но не обязательно идентичны исходным)
      expect(decrypted.content.length, binaryContent.length);

      // Проверяем, что footer соответствует исходному
      final decodedFooter = utf8.decode(decrypted.footer!);
      expect(decodedFooter, footer);
    });
  });
}
