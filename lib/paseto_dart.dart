// SPDX-FileCopyrightText: 2025 Karim "nogipx" Mamatkazin <nogipx@gmail.com>
//
// SPDX-License-Identifier: LGPL-3.0-or-later

library;

// Common exports
export 'utils/base64_ext.dart';
export 'models/crypto.dart';
export 'models/exceptions.dart' hide Signature;
export 'models/header.dart';
export 'models/message.dart';
export 'models/package.dart';
export 'models/payload.dart';
export 'models/purpose.dart';
export 'models/token.dart';
export 'models/version.dart';
export 'utils/registry_init.dart';

// Implementations
export 'crypto/x_chacha20_poly1305.dart';
export 'crypto/ed25519.dart';

// Version implementations
export 'versions/local_v2.dart' show LocalV2;
export 'versions/local_v3.dart' show LocalV3;
export 'versions/local_v4.dart' show LocalV4;
export 'versions/public_v2.dart' show PublicV2;
export 'versions/public_v3.dart' show PublicV3;
export 'versions/public_v4.dart' show PublicV4;
