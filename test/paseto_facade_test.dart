// SPDX-FileCopyrightText: 2026 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: MIT

import 'package:paseto_dart/paseto_dart.dart';
import 'package:test/test.dart';

void main() {
  group('Paseto facade', () {
    test('nanoId generates correct length and alphabet', () {
      final id = Paseto.nanoId();
      expect(id.length, NanoId.defaultSize);
      expect(id.split('').every(NanoId.defaultAlphabet.contains), isTrue);
      final id2 = Paseto.nanoId();
      expect(id2, isNot(id));
    });

    test('salt base64 roundtrip', () {
      final salt = Paseto.generatePasswordSalt(length: 24);
      final encoded = salt.toBase64();
      final decoded = PaserkSalt.fromBase64(encoded);
      expect(decoded.bytes, salt.bytes);
      expect(encoded, isNotEmpty);
    });

    test('symmetric key paserk roundtrip and identifier', () {
      final key = Paseto.generateSymmetricKey();
      final paserk = Paseto.symmetricKeyToPaserk(key);
      final restored = Paseto.symmetricKeyFromPaserk(paserk);
      expect(restored.toPaserk(), paserk);
      final lid = Paseto.symmetricKeyIdentifier(restored);
      expect(lid, isNotEmpty);
      key.dispose();
      restored.dispose();
    });

    test('symmetric key password and wrap/seal flows', () async {
      final key = Paseto.generateSymmetricKey();
      final salt = Paseto.generatePasswordSalt();
      final derived = await Paseto.symmetricKeyFromPassword(
        password: 'test-pass',
        salt: salt,
      );
      final paserkPw = await Paseto.symmetricKeyToPaserkPassword(
        key: key,
        password: 'test-pass',
      );
      final fromPw = await Paseto.symmetricKeyFromPaserkPassword(
        paserk: paserkPw,
        password: 'test-pass',
      );
      final wrap = Paseto.symmetricKeyToPaserkWrap(
        key: key,
        wrappingKey: derived,
      );
      final fromWrap = Paseto.symmetricKeyFromPaserkWrap(
        paserk: wrap,
        wrappingKey: derived,
      );
      expect(fromPw.toPaserk(), key.toPaserk());
      expect(fromWrap.toPaserk(), key.toPaserk());
      final pair = await Paseto.generateKeyPair();
      final seal = await Paseto.symmetricKeyToPaserkSeal(
        key: key,
        publicKey: pair.publicKey,
      );
      final fromSeal = await Paseto.symmetricKeyFromPaserkSeal(
        paserk: seal,
        keyPair: pair,
      );
      expect(fromSeal.toPaserk(), key.toPaserk());
      key.dispose();
      derived.dispose();
      fromPw.dispose();
      fromWrap.dispose();
      fromSeal.dispose();
      pair.dispose();
    });

    test('symmetric key from password deterministic', () async {
      final salt = Paseto.generatePasswordSalt();
      final k1 = await Paseto.symmetricKeyFromPassword(
        password: 'pwd',
        salt: salt,
      );
      final k2 = await Paseto.symmetricKeyFromPassword(
        password: 'pwd',
        salt: salt,
      );
      expect(k1.toPaserk(), k2.toPaserk());
      k1.dispose();
      k2.dispose();
    });

    test('symmetric key from bytes', () {
      final key = Paseto.generateSymmetricKey();
      final paserk = key.toPaserk();
      final raw =
          SafeBase64.decode(paserk.substring(PaserkKey.k4LocalPrefix.length));
      final restored = Paseto.symmetricKeyFromBytes(raw);
      expect(restored.toPaserk(), paserk);
      key.dispose();
      restored.dispose();
    });

    test('encrypt/decrypt local', () async {
      final key = Paseto.generateSymmetricKey();
      final payload = {
        'user': 'alice',
        'scope': ['read', 'write']
      };
      final token = await Paseto.encryptLocal(payload: payload, key: key);
      final decoded = await Paseto.decryptLocal(token: token, key: key);
      expect(decoded, payload);
      key.dispose();
    });

    test('encrypt/decrypt local with implicit assertion success/fail',
        () async {
      final key = Paseto.generateSymmetricKey();
      final payload = {'ok': true};
      final token = await Paseto.encryptLocal(
        payload: payload,
        key: key,
        implicitAssertion: 'ia',
      );
      final decoded = await Paseto.decryptLocal(
        token: token,
        key: key,
        implicitAssertion: 'ia',
      );
      expect(decoded, payload);
      await expectLater(
        Paseto.decryptLocal(
          token: token,
          key: key,
          implicitAssertion: 'wrong',
        ),
        throwsA(isA<Exception>()),
      );
      key.dispose();
    });

    test('sign/verify public', () async {
      final pair = await Paseto.generateKeyPair();
      final payload = {'sub': 'user1', 'admin': true};
      final token = await Paseto.signPublicToken(
        payload: payload,
        keyPair: pair,
        footer: '{"kid":"kid-1"}',
        implicitAssertion: 'ia',
      );
      final public = pair.publicKey;
      final verified = await Paseto.verifyPublicToken(
        token: token,
        publicKey: public,
        implicitAssertion: 'ia',
      );
      expect(verified, payload);
      pair.dispose();
    });

    test('sign/verify public implicit assertion mismatch throws', () async {
      final pair = await Paseto.generateKeyPair();
      final payload = {'x': 1};
      final token = await Paseto.signPublicToken(
        payload: payload,
        keyPair: pair,
        implicitAssertion: 'ia',
      );
      await expectLater(
        Paseto.verifyPublicToken(
          token: token,
          publicKey: pair.publicKey,
          implicitAssertion: 'wrong',
        ),
        throwsA(isA<Exception>()),
      );
      pair.dispose();
    });

    test('encryptForPublicKey/decryptForKeyPair', () async {
      final pair = await Paseto.generateKeyPair();
      final data = {'secret': 'value', 'n': 1};
      final token = await Paseto.encryptForPublicKey(
        data: data,
        publicKey: pair.publicKey,
      );
      final decoded =
          await Paseto.decryptForKeyPair(token: token, keyPair: pair);
      expect(decoded, data);
      pair.dispose();
    });

    test('withSecretKey disposeAfter', () async {
      final key = Paseto.generateSymmetricKey();
      final result =
          await key.withSecretKey((_) async => 42, disposeAfter: true);
      expect(result, 42);
      expect(() => key.toPaserk(), throwsA(isA<StateError>()));
    });

    test('withKeyPair disposeAfter', () async {
      final pair = await Paseto.generateKeyPair();
      final pubPaserk = pair.publicPaserk;
      final result = await pair.withKeyPair((_) async => 7, disposeAfter: true);
      expect(result, 7);
      expect(() => pair.toPaserk(), throwsA(isA<StateError>()));
      expect(() => pair.publicPaserk, throwsA(isA<StateError>()));
      // publicPaserk evaluated before disposeAfter flag, so store earlier
      expect(pubPaserk, isNotEmpty);
    });

    test('key pair paserk helpers and identifiers', () async {
      final pair = await Paseto.generateKeyPair();
      final paserk = Paseto.keyPairToPaserk(pair);
      final sid = Paseto.keyPairIdentifier(pair);
      final pid = Paseto.keyPairPublicIdentifier(pair);
      final pubPaserk = Paseto.keyPairPublicPaserk(pair);

      final raw =
          SafeBase64.decode(paserk.substring(PaserkKey.k4SecretPrefix.length));
      final privBytes = raw.sublist(0, 32);
      final pubBytes = raw.sublist(32);
      final fromBytes = Paseto.keyPairFromBytes(
        privateKeyBytes: privBytes,
        publicKeyBytes: pubBytes,
      );

      expect(Paseto.keyPairToPaserk(fromBytes), paserk);
      expect(Paseto.keyPairIdentifier(fromBytes), sid);
      expect(Paseto.keyPairPublicIdentifier(fromBytes), pid);
      expect(Paseto.publicKeyFromPaserk(pubPaserk).identifier, pid);
      pair.dispose();
      fromBytes.dispose();
    });

    test('isPaserk recognises prefixes', () {
      final key = Paseto.generateSymmetricKey();
      expect(Paseto.isPaserk(key.toPaserk()), isTrue);
      expect(Paseto.isPaserk('v4.local.payload'), isFalse);
      key.dispose();
    });

    test('generatePasswordSalt rejects too short', () {
      expect(
        () => Paseto.generatePasswordSalt(length: 8),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('key pair password and wrap flows', () async {
      final pair = await Paseto.generateKeyPair();
      final wrapKey = Paseto.generateSymmetricKey();

      final pwPaserk = await Paseto.keyPairToPaserkPassword(
        keyPair: pair,
        password: 'strong-pass',
      );
      final fromPw = await Paseto.keyPairFromPaserkPassword(
        paserk: pwPaserk,
        password: 'strong-pass',
      );
      expect(Paseto.keyPairToPaserk(fromPw), Paseto.keyPairToPaserk(pair));

      final wrapPaserk = Paseto.keyPairToPaserkWrap(
        keyPair: pair,
        wrappingKey: wrapKey,
      );
      final fromWrap = Paseto.keyPairFromPaserkWrap(
        paserk: wrapPaserk,
        wrappingKey: wrapKey,
      );
      expect(Paseto.keyPairToPaserk(fromWrap), Paseto.keyPairToPaserk(pair));

      pair.dispose();
      wrapKey.dispose();
      fromPw.dispose();
      fromWrap.dispose();
    });
  });
}
