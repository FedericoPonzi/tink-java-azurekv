# Security Policy

## Supported versions

This project is distributed via [JitPack](https://jitpack.io/). Security fixes are applied to
the latest released tag. Older versions are not maintained.

| Version | Supported |
| --- | --- |
| Latest release | ✅ |
| Older releases | ❌ |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use one of the following private channels:

- Open a private advisory via GitHub's
  [private vulnerability reporting](https://github.com/FedericoPonzi/tink-java-azurekv/security/advisories/new)
  (preferred). This requires GitHub Security Advisories to be enabled for the repository.
- If private advisories are unavailable, contact the maintainer privately (for example, via the
  email on the [maintainer's GitHub profile](https://github.com/FedericoPonzi)) instead of
  filing a public issue.

Please include as much of the following as you can:

- A description of the vulnerability and its impact.
- Steps to reproduce or a proof of concept.
- Affected version(s) / commit.
- Any suggested mitigation, if known.

## What to expect

- **Acknowledgement:** we aim to acknowledge your report within a few business days.
- **Updates:** we will keep you informed of progress while we investigate and prepare a fix.
- **Disclosure:** we follow coordinated disclosure and will publish an advisory once a fix is
  available. We are happy to credit reporters who wish to be acknowledged.

## Scope

This project forwards cryptographic operations to Azure Key Vault. Vulnerabilities in Azure
Key Vault itself or in upstream dependencies ([Tink](https://github.com/tink-crypto/tink-java),
the [Azure SDK](https://github.com/Azure/azure-sdk-for-java)) should be reported to their
respective maintainers.
