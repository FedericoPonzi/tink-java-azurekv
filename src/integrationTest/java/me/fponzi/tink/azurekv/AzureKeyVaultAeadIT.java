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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assume.assumeTrue;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.core.http.HttpClient;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.google.crypto.tink.Aead;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import org.junit.After;
import org.junit.Test;
import reactor.core.publisher.Mono;

/**
 * Record/replay integration test that exercises {@link AzureKeyVaultAead} (and {@link
 * CryptographyClientCrypto}) against the <em>real</em> Azure Managed HSM AES-256-GCM wire protocol
 * via the self-contained {@link RecordingHttpClient}.
 *
 * <p>It drives a genuine {@link CryptographyClient}, so on RECORD it verifies that Key Vault
 * accepts the request we build and on PLAYBACK it verifies that the request bytes we produce still
 * match the committed recording and that we parse the {@code iv}, {@code tag} and ciphertext out of
 * a real response. It does <strong>not</strong> verify cryptography — on playback the recorded
 * ciphertext is simply replayed (verifying AES-GCM is Azure's job, not this library's).
 *
 * <p>The test lives in an isolated {@code integrationTest} source set and is never part of the
 * default {@code build}. Without a committed recording it is skipped. See {@code
 * docs/test-recording.md} for the recording and sanitization procedure.
 *
 * <pre>{@code
 * # one-time recording against a live Managed HSM (incurs cost):
 * AZURE_TEST_MODE=RECORD \
 *   AZURE_MANAGED_HSM_KEY_ID="https://<hsm>.managedhsm.azure.net/keys/<name>/<version>" \
 *   ./gradlew integrationTest
 *
 * # offline replay of the committed recording (no Azure, no cost):
 * ./gradlew integrationTest
 * }</pre>
 */
public class AzureKeyVaultAeadIT {

  private static final String RECORDING_NAME = "AzureKeyVaultAeadIT.encryptThenDecrypt_roundTrips";

  /** Synthetic identifier used on playback; the sanitizers rewrite the live values to these. */
  private static final String PLAYBACK_KEY_IDENTIFIER =
      "https://myhsm.managedhsm.azure.net/keys/testkey/testversion";

  private static final String SANITIZED_HOST = "myhsm.managedhsm.azure.net";

  /** Redactions applied at record time and to incoming requests before matching on playback. */
  private static final List<RecordingHttpClient.Sanitizer> SANITIZERS =
      Arrays.asList(
          // HSM host name in URLs, bodies (the response `kid`) and the WWW-Authenticate header.
          new RecordingHttpClient.Sanitizer(
              "[A-Za-z0-9-]+\\.managedhsm\\.azure\\.net", SANITIZED_HOST),
          // Key name/version in URLs and in the response `kid` (a versioned key id is required).
          new RecordingHttpClient.Sanitizer("(?<=/keys/)[^/?\"]+/[^/?\"]+", "testkey/testversion"),
          // Tenant/object GUIDs (e.g. in the WWW-Authenticate authorization URL).
          new RecordingHttpClient.Sanitizer(
              "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
              "00000000-0000-0000-0000-000000000000"));

  private static final Pattern VERSIONED_KEY_ID =
      Pattern.compile("https://[^/]+/keys/[^/]+/[^/]+/?$");

  private RecordingHttpClient httpClient;

  @After
  public void persistRecording() throws Exception {
    if (isRecordMode() && httpClient != null) {
      httpClient.persist();
    }
  }

  @Test
  public void encryptThenDecrypt_roundTrips() throws Exception {
    if (!isRecordMode()) {
      assumeTrue(
          "No committed recording for " + RECORDING_NAME + "; skipping replay.",
          RecordingHttpClient.hasRecording(RECORDING_NAME));
    }

    Aead aead = AzureKeyVaultAead.create(new CryptographyClientCrypto(buildClient()));
    byte[] plaintext = "hello azure managed hsm".getBytes(StandardCharsets.UTF_8);
    byte[] associatedData = "tink-azurekv".getBytes(StandardCharsets.UTF_8);

    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    byte[] decrypted = aead.decrypt(ciphertext, associatedData);

    assertThat(decrypted).isEqualTo(plaintext);
  }

  private CryptographyClient buildClient() {
    TokenCredential credential;
    String keyIdentifier;
    if (isRecordMode()) {
      credential = new DefaultAzureCredentialBuilder().build();
      keyIdentifier = recordingKeyIdentifier();
      httpClient =
          RecordingHttpClient.recording(RECORDING_NAME, HttpClient.createDefault(), SANITIZERS);
    } else {
      credential = staticTokenCredential();
      keyIdentifier = PLAYBACK_KEY_IDENTIFIER;
      httpClient = RecordingHttpClient.playback(RECORDING_NAME, SANITIZERS);
    }

    return new CryptographyClientBuilder()
        .keyIdentifier(keyIdentifier)
        .credential(credential)
        .httpClient(httpClient)
        // Force remote crypto so encrypt/decrypt are POSTs we can record (no local JWK fetch).
        .disableKeyCaching()
        .buildClient();
  }

  private static String recordingKeyIdentifier() {
    String keyId = System.getenv("AZURE_MANAGED_HSM_KEY_ID");
    if (keyId == null || !VERSIONED_KEY_ID.matcher(keyId).matches()) {
      throw new IllegalStateException(
          "AZURE_MANAGED_HSM_KEY_ID must be a versioned A256GCM key on an Azure Managed HSM, e.g."
              + " https://<hsm>.managedhsm.azure.net/keys/<name>/<version> (the version is required"
              + " so the key path can be sanitized unambiguously).");
    }
    return keyId;
  }

  private static boolean isRecordMode() {
    return "RECORD".equalsIgnoreCase(System.getenv("AZURE_TEST_MODE"));
  }

  /** A credential that returns a fixed, non-expiring token without any network call. */
  private static TokenCredential staticTokenCredential() {
    return request ->
        Mono.just(new AccessToken("playback-token", OffsetDateTime.now().plusHours(1)));
  }
}
