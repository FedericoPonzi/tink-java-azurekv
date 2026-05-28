# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0]

### Changed
- Upgraded Google Tink from 1.15.0 to 1.21.0.

### Added
- Tightened `azure-kv://` URI validation to require the `<host>/keys/<name>[/<version>]`
  structure, failing fast on malformed key URIs.

## [0.1.0]

### Added
- Initial release: a Google Tink `KmsClient` integration for Azure Key Vault (Managed HSM).
- AES-256-GCM (`A256GCM`) remote AEAD via `AzureKeyVaultClient` / `AzureKeyVaultAead`.
- `AzureKeyVaultClient.register(...)` convenience for the Tink `KmsClients` registry.
- Authenticated ciphertext framing (`version || ivLen || iv || tagLen || tag || ciphertext`).
- Gradle (Kotlin DSL) build, JitPack distribution, CI and tag-based release workflows.

[Unreleased]: https://github.com/FedericoPonzi/tink-java-azurekv/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/FedericoPonzi/tink-java-azurekv/releases/tag/v0.1.0
