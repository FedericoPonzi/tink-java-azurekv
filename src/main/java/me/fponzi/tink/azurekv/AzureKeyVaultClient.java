// Copyright 2026 Federico Ponzi
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package me.fponzi.tink.azurekv;

import com.azure.core.credential.TokenCredential;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.KmsClients;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.security.GeneralSecurityException;
import java.util.Locale;
import java.util.regex.Pattern;
import javax.annotation.Nullable;

/**
 * An implementation of {@link KmsClient} for <a
 * href="https://learn.microsoft.com/azure/key-vault/">Azure Key Vault</a>.
 *
 * <p>Encryption uses AES-256-GCM ({@code A256GCM}), which is authenticated and supports associated
 * data. The bound key must therefore be a symmetric AES key (e.g. on an Azure Managed HSM).
 *
 * <p>Key URIs have the form {@code
 * azure-kv://<hsm>.managedhsm.azure.net/keys/<name>/<version>}, which mirrors the Azure key
 * identifier with the {@code https} scheme replaced by {@link #PREFIX}. The {@code <version>} is
 * optional. A256GCM requires a symmetric AES key, which is only available on Azure Managed HSM.
 */
public final class AzureKeyVaultClient implements KmsClient {
  public static final String PREFIX = "azure-kv://";

  /**
   * Matches the key-identifier portion of a URI (after {@link #PREFIX}): {@code
   * <host>/keys/<name>} with an optional {@code /<version>} suffix.
   */
  private static final Pattern KEY_URI_PATTERN = Pattern.compile("[^/]+/keys/[^/]+(?:/[^/]+)?");

  @Nullable private final TokenCredential credential;
  @Nullable private final String keyUri;

  private AzureKeyVaultClient(@Nullable TokenCredential credential, @Nullable String keyUri) {
    if (keyUri != null && !keyUri.toLowerCase(Locale.US).startsWith(PREFIX)) {
      throw new IllegalArgumentException("key URI must start with " + PREFIX);
    }
    this.credential = credential;
    this.keyUri = keyUri;
  }

  /**
   * Constructs a client that is not bound to a key URI.
   *
   * @param credential the Azure credential to authenticate with
   * @return a new {@link KmsClient} that supports any {@code azure-kv://} URI
   */
  public static KmsClient create(TokenCredential credential) {
    return new AzureKeyVaultClient(credential, null);
  }

  /**
   * Constructs a client bound to a single key identified by {@code keyUri}.
   *
   * @param credential the Azure credential to authenticate with
   * @param keyUri the {@code azure-kv://} key URI this client is bound to
   * @return a new {@link KmsClient} that only supports {@code keyUri}
   */
  public static KmsClient create(TokenCredential credential, String keyUri) {
    return new AzureKeyVaultClient(credential, keyUri);
  }

  /**
   * Creates a client and registers it with Tink's {@link KmsClients} registry, so that a {@code
   * KmsClient} can be looked up automatically (for example by {@code KmsClients.get(keyUri)} when
   * building an envelope AEAD).
   *
   * @param keyUri the key URI to bind the client to, or {@code null} to register an unbound client
   * @param credential the Azure credential to authenticate with
   */
  public static void register(@Nullable String keyUri, TokenCredential credential) {
    KmsClients.add(new AzureKeyVaultClient(credential, keyUri));
  }

  @Override
  public boolean doesSupport(String uri) {
    if (this.keyUri != null && !this.keyUri.isEmpty()) {
      return this.keyUri.equals(uri);
    }
    return uri.toLowerCase(Locale.US).startsWith(PREFIX);
  }

  @Override
  @CanIgnoreReturnValue
  public KmsClient withCredentials(String credentialPath) throws GeneralSecurityException {
    throw new UnsupportedOperationException(
        "AzureKeyVaultClient does not support loading credentials from a file");
  }

  /** Returns a new client that authenticates with {@link DefaultAzureCredentialBuilder}. */
  @Override
  @CanIgnoreReturnValue
  public KmsClient withDefaultCredentials() throws GeneralSecurityException {
    return new AzureKeyVaultClient(new DefaultAzureCredentialBuilder().build(), this.keyUri);
  }

  /** Converts an {@code azure-kv://} URI into an Azure Key Vault key identifier. */
  static String getKeyIdentifier(String uri) throws GeneralSecurityException {
    if (!uri.toLowerCase(Locale.US).startsWith(PREFIX)) {
      throw new GeneralSecurityException("key URI must start with " + PREFIX);
    }
    String rest = uri.substring(PREFIX.length());
    if (!KEY_URI_PATTERN.matcher(rest).matches()) {
      throw new GeneralSecurityException(
          "malformed key URI; expected " + PREFIX + "<host>/keys/<name>[/<version>] but got " + uri);
    }
    return "https://" + rest;
  }

  @Override
  public Aead getAead(String uri) throws GeneralSecurityException {
    if (this.keyUri != null && !this.keyUri.equals(uri)) {
      throw new GeneralSecurityException(
          String.format(
              "this client is bound to %s, cannot load keys bound to %s", this.keyUri, uri));
    }
    if (this.credential == null) {
      throw new GeneralSecurityException(
          "no credentials configured; create the client with a TokenCredential or call"
              + " withDefaultCredentials()");
    }
    try {
      KeyVaultCrypto crypto =
          new CryptographyClientCrypto(
              new CryptographyClientBuilder()
                  .keyIdentifier(getKeyIdentifier(uri))
                  .credential(this.credential)
                  .buildClient());
      return AzureKeyVaultAead.create(crypto);
    } catch (RuntimeException e) {
      throw new GeneralSecurityException("cannot build Azure Key Vault client", e);
    }
  }
}
