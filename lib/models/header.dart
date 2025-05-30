// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

import 'dart:convert';

import 'package:equatable/equatable.dart';
import 'package:meta/meta.dart';
import 'package:paseto_dart/paseto_dart.dart';

@immutable
final class Header extends Equatable {
  const Header({
    required this.version,
    required this.purpose,
  });

  final Version version;
  final Purpose purpose;

  String get toTokenString {
    return '${[version.name, purpose.name].join('.')}.';
  }

  List<int> get bytes {
    return utf8.encode(toTokenString);
  }

  @override
  List<Object?> get props => [
        version,
        purpose,
      ];
}
