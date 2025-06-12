import 'dart:convert';
import 'dart:typed_data';

import 'package:paseto_dart/paseto_dart.dart';
import 'package:test/test.dart';

void main() {
  group('Comprehensive Models Tests', () {
    group('Package Tests', () {
      test('создание пакета с контентом и футером', () {
        final content = utf8.encode('test content');
        final footer = utf8.encode('test footer');

        final package = Package(content: content, footer: footer);

        expect(package.content, equals(content));
        expect(package.footer, equals(footer));
      });

      test('создание пакета только с контентом', () {
        final content = utf8.encode('test content');

        final package = Package(content: content);

        expect(package.content, equals(content));
        expect(package.footer, isNull);
      });

      test('пакет с пустым контентом', () {
        final package = Package(content: Uint8List(0));

        expect(package.content, isEmpty);
        expect(package.footer, isNull);
      });

      test('пакет с очень большим контентом', () {
        final largeContent =
            Uint8List.fromList(List.generate(10000, (i) => i % 256));

        final package = Package(content: largeContent);

        expect(package.content.length, equals(10000));
        expect(package.content[100], equals(100));
        expect(package.content[9999], equals(15)); // 9999 % 256 = 15
      });

      test('пакет с бинарными данными', () {
        final binaryData = Uint8List.fromList([0, 1, 255, 128, 64]);

        final package = Package(content: binaryData);

        expect(package.content, equals(binaryData));
      });

      test('equality и hashCode для Package', () {
        final content1 = utf8.encode('test');
        final footer1 = utf8.encode('footer');

        final package1 = Package(content: content1, footer: footer1);
        final package2 = Package(content: content1, footer: footer1);
        final package3 = Package(content: utf8.encode('different'));

        expect(package1, equals(package2));
        expect(package1.hashCode, equals(package2.hashCode));
        expect(package1, isNot(equals(package3)));
      });
    });

    group('Message Tests', () {
      test('создание сообщения со всеми компонентами', () {
        final header = Header(version: Version.v4, purpose: Purpose.local);
        final content = utf8.encode('test message');
        final footer = utf8.encode('test footer');
        final package = Package(content: content, footer: footer);
        final payload = PayloadLocal(
          nonce: Mac(Uint8List(32)),
          secretBox: SecretBox(
            Uint8List.fromList([1, 2, 3]),
            nonce: Uint8List(12),
            mac: Mac(Uint8List(32)),
          ),
        );

        final message = Message(
          header: header,
          package: package,
          payload: payload,
        );

        expect(message.header, equals(header));
        expect(message.package, equals(package));
        expect(message.payload, equals(payload));
      });

      test('сообщение с минимальными данными', () {
        final header = Header(version: Version.v4, purpose: Purpose.local);
        final package = Package(content: Uint8List(0));
        final payload = PayloadLocal(
          nonce: Mac(Uint8List(32)),
          secretBox: SecretBox(
            Uint8List(0),
            nonce: Uint8List(12),
            mac: Mac(Uint8List(32)),
          ),
        );

        final message = Message(
          header: header,
          package: package,
          payload: payload,
        );

        expect(message.header.version, equals(Version.v4));
        expect(message.header.purpose, equals(Purpose.local));
        expect(message.package.content, isEmpty);
      });

      test('сообщение с разными типами payload', () {
        final header = Header(version: Version.v4, purpose: Purpose.public);
        final package = Package(content: utf8.encode('public message'));
        final payload = PayloadPublic(
          message: utf8.encode('signed message'),
          signature: Uint8List.fromList(List.generate(64, (i) => i)),
        );

        final message = Message(
          header: header,
          package: package,
          payload: payload,
        );

        expect(message.header.purpose, equals(Purpose.public));
        expect(message.payload, isA<PayloadPublic>());
      });

      test('equality для Message', () {
        final header = Header(version: Version.v4, purpose: Purpose.local);
        final package = Package(content: utf8.encode('test'));
        final payload = PayloadLocal(
          nonce: Mac(Uint8List(32)),
          secretBox: SecretBox(
            Uint8List.fromList([1, 2, 3]),
            nonce: Uint8List(12),
            mac: Mac(Uint8List(32)),
          ),
        );

        final message1 =
            Message(header: header, package: package, payload: payload);
        final message2 =
            Message(header: header, package: package, payload: payload);

        expect(message1, equals(message2));
      });
    });

    group('PayloadLocal Extended Tests', () {
      test('PayloadLocal с payloadBytes', () {
        final nonce = Mac(Uint8List.fromList(List.generate(32, (i) => i)));
        final cipherText =
            Uint8List.fromList(List.generate(50, (i) => i + 100));
        final mac = Mac(Uint8List.fromList(List.generate(32, (i) => i + 200)));
        final secretBox = SecretBox(cipherText, nonce: Uint8List(12), mac: mac);
        final payloadBytes = List<int>.from(nonce.bytes)..addAll(cipherText);

        final payload = PayloadLocal(
          nonce: nonce,
          secretBox: secretBox,
          mac: mac,
          payloadBytes: payloadBytes,
        );

        expect(payload.nonce, equals(nonce));
        expect(payload.secretBox, equals(secretBox));
        expect(payload.mac, equals(mac));
        expect(payload.payloadBytes, equals(payloadBytes));
      });

      test('PayloadLocal toTokenString с payloadBytes', () {
        final payloadBytes = List.generate(64, (i) => i);

        final payload = PayloadLocal(
          nonce: null,
          secretBox: null,
          mac: null,
          payloadBytes: payloadBytes,
        );

        final tokenString = payload.toTokenString;
        final decoded = SafeBase64.decode(tokenString);

        expect(decoded, equals(payloadBytes));
      });

      test('PayloadLocal toTokenString без payloadBytes', () {
        final nonce = Mac(Uint8List.fromList(List.generate(10, (i) => i)));
        final cipherText = Uint8List.fromList(List.generate(20, (i) => i + 10));
        final mac = Mac(Uint8List.fromList(List.generate(10, (i) => i + 30)));
        final secretBox = SecretBox(cipherText, nonce: Uint8List(12), mac: mac);

        final payload = PayloadLocal(
          nonce: nonce,
          secretBox: secretBox,
          mac: mac,
        );

        final tokenString = payload.toTokenString;
        final decoded = SafeBase64.decode(tokenString);

        // Должен содержать nonce + cipherText + mac
        expect(decoded.length, equals(10 + 20 + 10));
        expect(decoded.sublist(0, 10), equals(nonce.bytes));
        expect(decoded.sublist(10, 30), equals(cipherText));
        expect(decoded.sublist(30, 40), equals(mac.bytes));
      });

      test('PayloadLocal с null компонентами', () {
        final payload = PayloadLocal(
          nonce: null,
          secretBox: null,
          mac: null,
        );

        final tokenString = payload.toTokenString;

        expect(tokenString,
            equals('')); // Если все null, то результат должен быть пустым
        expect(SafeBase64.decode(tokenString), isEmpty);
      });
    });

    group('PayloadPublic Extended Tests', () {
      test('PayloadPublic с сообщением и подписью', () {
        final message = utf8.encode('Подписанное сообщение');
        final signature = Uint8List.fromList(List.generate(64, (i) => i));

        final payload = PayloadPublic(message: message, signature: signature);

        expect(payload.message, equals(message));
        expect(payload.signature, equals(signature));
        expect(payload.stringMessage, equals('Подписанное сообщение'));
      });

      test('PayloadPublic stringMessage свойство', () {
        final message = utf8.encode('Test message with русский текст');
        final payload = PayloadPublic(message: message);

        expect(
            payload.stringMessage, equals('Test message with русский текст'));
      });

      test('PayloadPublic jsonContent - валидный JSON', () {
        final jsonData = {'name': 'test', 'value': 42, 'active': true};
        final message = utf8.encode(json.encode(jsonData));
        final payload = PayloadPublic(message: message);

        final decoded = payload.jsonContent;

        expect(decoded, isNotNull);
        expect(decoded!['name'], equals('test'));
        expect(decoded['value'], equals(42));
        expect(decoded['active'], equals(true));
      });

      test('PayloadPublic jsonContent - невалидный JSON', () {
        final message = utf8.encode('это не JSON');
        final payload = PayloadPublic(message: message);

        expect(payload.jsonContent, isNull);
      });

      test('PayloadPublic toTokenString с подписью', () {
        final message = utf8.encode('test message');
        final signature = Uint8List.fromList([1, 2, 3, 4]);
        final payload = PayloadPublic(message: message, signature: signature);

        final tokenString = payload.toTokenString;
        final decoded = SafeBase64.decode(tokenString);

        expect(decoded.length, equals(message.length + signature.length));
        expect(decoded.sublist(0, message.length), equals(message));
        expect(decoded.sublist(message.length), equals(signature));
      });

      test('PayloadPublic toTokenString без подписи', () {
        final message = utf8.encode('test message without signature');
        final payload = PayloadPublic(message: message);

        final tokenString = payload.toTokenString;
        final decoded = SafeBase64.decode(tokenString);

        expect(decoded, equals(message));
      });

      test('PayloadPublic с пустым сообщением', () {
        final payload = PayloadPublic(message: Uint8List(0));

        expect(payload.message, isEmpty);
        expect(payload.stringMessage, isEmpty);
        expect(payload.jsonContent, isNull);
      });

      test('PayloadPublic с бинарными данными', () {
        final binaryMessage = Uint8List.fromList([0, 255, 128, 64]);
        final payload = PayloadPublic(message: binaryMessage);

        expect(payload.message, equals(binaryMessage));
        // stringMessage может содержать невалидные UTF-8 символы
      });
    });

    group('Header Extended Tests', () {
      test('все комбинации версий и целей', () {
        for (final version in Version.values) {
          for (final purpose in Purpose.values) {
            final header = Header(version: version, purpose: purpose);

            expect(header.version, equals(version));
            expect(header.purpose, equals(purpose));
            expect(header.toTokenString, contains(version.name));
            expect(header.toTokenString, contains(purpose.name));
          }
        }
      });

      test('Header toTokenString формат', () {
        final header = Header(version: Version.v4, purpose: Purpose.local);

        expect(header.toTokenString, equals('v4.local.'));
      });

      test('Header equality', () {
        final header1 = Header(version: Version.v4, purpose: Purpose.local);
        final header2 = Header(version: Version.v4, purpose: Purpose.local);
        final header3 = Header(version: Version.v4, purpose: Purpose.public);

        expect(header1, equals(header2));
        expect(header1.hashCode, equals(header2.hashCode));
        expect(header1, isNot(equals(header3)));
      });

      test('Header immutability', () {
        final header = Header(version: Version.v4, purpose: Purpose.local);

        // Нельзя изменить свойства после создания
        expect(header.version, equals(Version.v4));
        expect(header.purpose, equals(Purpose.local));
      });
    });

    group('Integration Tests for Models', () {
      test('полный цикл создания и парсинга токена', () async {
        // Создаем все компоненты
        final secretKey = SecretKey(List.generate(32, (i) => i));
        final content = utf8.encode('{"message": "integration test"}');
        final footer = utf8.encode('{"kid": "test-key"}');

        // Создаем пакет
        final package = Package(content: content, footer: footer);

        // Шифруем
        final encryptedPayload =
            await LocalV4.encrypt(package, secretKey: secretKey);

        // Создаем токен
        final token = Token(
          header: LocalV4.header,
          payload: encryptedPayload,
          footer: footer,
        );

        // Преобразуем в строку и обратно
        final tokenString = token.toTokenString;
        final parsedToken = await Token.fromString(tokenString);

        // Дешифруем
        final decryptedMessage =
            await parsedToken.decryptLocalMessage(secretKey: secretKey);

        // Проверяем все компоненты
        expect(decryptedMessage.header.version, equals(Version.v4));
        expect(decryptedMessage.header.purpose, equals(Purpose.local));
        expect(utf8.decode(decryptedMessage.package.content),
            equals('{"message": "integration test"}'));
        expect(utf8.decode(decryptedMessage.package.footer!),
            equals('{"kid": "test-key"}'));
      });

      test('работа с разными типами данных в Package', () {
        final testCases = [
          {'name': 'JSON', 'data': utf8.encode('{"key": "value"}')},
          {'name': 'Plain text', 'data': utf8.encode('Hello, World!')},
          {
            'name': 'Binary',
            'data': Uint8List.fromList([0, 255, 128, 64])
          },
          {'name': 'Empty', 'data': Uint8List(0)},
          {
            'name': 'Large',
            'data': Uint8List.fromList(List.generate(1000, (i) => i % 256))
          },
        ];

        for (final testCase in testCases) {
          final package = Package(content: testCase['data'] as List<int>);

          expect(package.content, equals(testCase['data']));
          expect(package.content.length,
              equals((testCase['data'] as List<int>).length));
        }
      });
    });
  });
}
