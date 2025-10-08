// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: MIT

import 'dart:typed_data';

import '../utils/base64_ext.dart';

abstract class PaserkKey {
  static const String k4LocalPrefix = 'k4.local.';
  static const String k4PublicPrefix = 'k4.public.';
  static const String k4SecretPrefix = 'k4.secret.';
  static const String k4LocalWrapPrefix = 'k4.local-wrap.';
  static const String k4SecretWrapPrefix = 'k4.secret-wrap.';
  static const String k4LocalWrapPiePrefix = 'k4.local-wrap.pie.';
  static const String k4SecretWrapPiePrefix = 'k4.secret-wrap.pie.';
  static const String k4LocalPwPrefix = 'k4.local-pw.';
  static const String k4SecretPwPrefix = 'k4.secret-pw.';
  static const String k4LidPrefix = 'k4.lid.';
  static const String k4PidPrefix = 'k4.pid.';
  static const String k4SidPrefix = 'k4.sid.';
  static const String k4SealPrefix = 'k4.seal.';

  final Uint8List rawBytes;
  final String prefix;

  PaserkKey(this.rawBytes, this.prefix);

  String encode() {
    return prefix + SafeBase64.encode(rawBytes);
  }

  @override
  String toString() => encode();

  static bool isPaserk(String data) {
    return data.startsWith('k4.');
  }

  static Uint8List decode(String data, String expectedPrefix) {
    if (!data.startsWith(expectedPrefix)) {
      throw ArgumentError('Invalid PASERK format: expected $expectedPrefix');
    }
    final list = SafeBase64.decode(data.substring(expectedPrefix.length));
    return Uint8List.fromList(list);
  }
}
