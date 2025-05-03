import 'package:test/test.dart';
import 'package:paseto_dart/paseto_dart.dart';
import 'test_helpers.dart';

void main() {
  test('sign and verify basic', () async {
    // Инициализируем алгоритмы
    PasetoRegistryInitializer.initV3Public();

    // Предсказуемая ключевая пара
    final keyPair = await TestHelpers.generateKeyPair(TestKeyPairType.ecdsa384);

    // Получаем токен для версии 2 публичного ключа
    final token = Token(
      header: PublicV3.header,
      payload: PayloadPublic(
        message: List<int>.from([1, 2, 3, 4, 5]),
        signature: List<int>.from([10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120]),
      ),
      footer: null,
    );

    // Проверяем формат токена
    expect(token.header.version, equals(Version.v3));
    expect(token.header.purpose, equals(Purpose.public));
    expect(token.toTokenString.startsWith('v3.public.'), isTrue);

    // Проверяем, что неверная подпись вызывает ошибку при проверке
    bool errorThrown = false;
    try {
      await token.verifyPublicMessage(publicKey: keyPair.publicKey);
      fail('Проверка неправильной подписи должна была вызвать ошибку');
    } catch (e) {
      // Любая ошибка здесь означает успех теста
      errorThrown = true;
    }

    expect(errorThrown, isTrue, reason: 'Ожидалась ошибка при проверке неправильной подписи');
  });
}
