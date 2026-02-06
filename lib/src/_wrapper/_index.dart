// SPDX-FileCopyrightText: 2026 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: MIT

import 'dart:convert';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:paseto_dart/paseto_dart.dart';

part 'paserk_key_pair.dart';
part 'paserk_public_key.dart';
part 'paserk_symmetric_key.dart';
part 'paserk_salt.dart';
part 'nanoid.dart';
part 'paseto.dart';

void _zero(List<int> bytes) {
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = 0;
  }
}
