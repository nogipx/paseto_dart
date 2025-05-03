import 'package:test/test.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;

void main() {
  test('check key lengths', () {
    final pair = ed.generateKey();
    print('Private key length: ${pair.privateKey.bytes.length}');
    print('Public key length: ${pair.publicKey.bytes.length}');

    // Проверим структуру
    print('Private key: ${pair.privateKey.bytes}');
    print('Public key: ${pair.publicKey.bytes}');
  });
}
