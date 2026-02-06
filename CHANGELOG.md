## 2.1.0
- Added high-level Paseto facade with PASERK-oriented wrappers (`PaserkSymmetricKey`, `PaserkKeyPair`, `PaserkPublicKey`) and safe `with...` helpers.
- Exposed full PASERK flows via the facade: k4.local/secret serialization, password, wrap, seal, identifiers, salt generation, and NanoID utility.
- Implemented public-key sealing convenience (`encryptForPublicKey` / `decryptForKeyPair`).
- Added comprehensive unit tests covering all facade scenarios.

## 2.0.0
- Adopted the MIT License for the project.
- Translated and refreshed the documentation for the upcoming release.
- Prepared metadata for the 2.0.0 publish by bumping the package version.

## 1.1.0
- Добавлена полная поддержка PASERK v4 (PIE wrap, password-based ключи и seal)
- Уменьшён Argon2 `memoryCost` по умолчанию для password-based ключей до 64 MiB
- Расширены тесты в соответствии с официальными векторами и Python-совместимостью
- Обновлена документация и CI для проверки межъязыковой совместимости

## 1.0.1
- Fix for passing reference vectors tests

## 1.0.0
- Initial release with Paseto v4 support.
