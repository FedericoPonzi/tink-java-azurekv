# tink-java-azurekv

[![CI](https://github.com/FedericoPonzi/tink-java-azurekv/actions/workflows/ci.yml/badge.svg)](https://github.com/FedericoPonzi/tink-java-azurekv/actions/workflows/ci.yml)
[![](https://jitpack.io/v/FedericoPonzi/tink-java-azurekv.svg)](https://jitpack.io/#FedericoPonzi/tink-java-azurekv)

A [Google Tink](https://github.com/tink-crypto/tink-java) KMS integration for
[Azure Key Vault](https://learn.microsoft.com/azure/key-vault/). It lets you use an Azure Key
Vault AES key as a Tink `Aead` for remote authenticated encryption/decryption (for example, to
wrap a Tink keyset).

It mirrors the design of the official Tink integrations
([`tink-java-hcvault`](https://github.com/tink-crypto/tink-java-hcvault),
[`tink-java-awskms`](https://github.com/tink-crypto/tink-java-awskms)).

## Algorithm

Encryption uses **AES-256-GCM** (`A256GCM`). AES-GCM is authenticated and supports associated
data natively, so this is a true AEAD. The bound key must therefore be a symmetric AES key,
which on Azure means an [Azure Managed HSM](https://learn.microsoft.com/azure/key-vault/managed-hsm/)
key (AES keys are not available on the standard vault tier).

The returned ciphertext bundles the Key-Vault-generated IV and authentication tag and is framed
as `version || ivLen || iv || tagLen || tag || ciphertext`.

## Key URI format

A key URI is the Azure key identifier with the `https` scheme replaced by `azure-kv://`. You pass
the full `azure-kv://...` URI to `AzureKeyVaultClient.create(...)` / `client.getAead(uri)`; the
library strips the prefix, prepends `https://`, and hands the resulting key identifier to the
Azure SDK.

Because AES keys (required for `A256GCM`) are only available on **Azure Managed HSM**, the host is
the Managed HSM endpoint (`.managedhsm.azure.net`), not the standard vault (`.vault.azure.net`):

```
azure-kv://<hsm-name>.managedhsm.azure.net/keys/<key-name>/<key-version>
```

The `<key-version>` segment is optional; omit it to use the key's latest version:

```
azure-kv://<hsm-name>.managedhsm.azure.net/keys/<key-name>
```

## Installation (JitPack)

Artifacts are built on demand by [JitPack](https://jitpack.io/) from git tags.

### Gradle (Kotlin DSL)

```kotlin
repositories {
    mavenCentral()
    maven("https://jitpack.io")
}

dependencies {
    implementation("com.github.FedericoPonzi:tink-java-azurekv:<version>")
}
```

### Maven

```xml
<repositories>
  <repository>
    <id>jitpack.io</id>
    <url>https://jitpack.io</url>
  </repository>
</repositories>

<dependency>
  <groupId>com.github.FedericoPonzi</groupId>
  <artifactId>tink-java-azurekv</artifactId>
  <version>VERSION</version>
</dependency>
```

Replace `<version>` with a released git tag (e.g. `v0.1.0`) or a commit hash. See
<https://jitpack.io/#FedericoPonzi/tink-java-azurekv> for available versions.

## Usage

```java
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KmsClient;
import me.fponzi.tink.azurekv.AzureKeyVaultClient;

String keyUri =
    "azure-kv://myhsm.managedhsm.azure.net/keys/mykey/00112233445566778899aabbccddeeff";

KmsClient client =
    AzureKeyVaultClient.create(new DefaultAzureCredentialBuilder().build(), keyUri);

Aead aead = client.getAead(keyUri);

byte[] ciphertext = aead.encrypt("secret".getBytes(), "context".getBytes());
byte[] plaintext = aead.decrypt(ciphertext, "context".getBytes());
```

## Building

Requires JDK 11+ (the Gradle toolchain auto-provisions JDK 11).

```bash
./gradlew build
```

## Versioning & releases

Releases follow [Semantic Versioning](https://semver.org/) and are cut by pushing a `vX.Y.Z`
git tag. The tag triggers a GitHub Release, and JitPack builds the same tag on demand. The
project version is derived from the current git tag at build time.

## Security

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities.

## License

Apache License 2.0. See [LICENSE](LICENSE).
