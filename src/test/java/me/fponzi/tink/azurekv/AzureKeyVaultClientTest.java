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
import static org.junit.Assert.assertThrows;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.KmsClients;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import reactor.core.publisher.Mono;

/** Tests for {@link AzureKeyVaultClient}. */
@RunWith(JUnit4.class)
public class AzureKeyVaultClientTest {
  private static final String KEY_URI =
      "azure-kv://myhsm.managedhsm.azure.net/keys/mykey/00112233445566778899aabbccddeeff";
  private static final String OTHER_KEY_URI =
      "azure-kv://myhsm.managedhsm.azure.net/keys/otherkey/00112233445566778899aabbccddeeff";

  private static final TokenCredential FAKE_CREDENTIAL =
      (request) -> Mono.<AccessToken>empty();

  @Test
  public void doesSupport_unboundClient() throws Exception {
    KmsClient client = AzureKeyVaultClient.create(FAKE_CREDENTIAL);
    assertThat(client.doesSupport(KEY_URI)).isTrue();
    assertThat(client.doesSupport("aws-kms://something")).isFalse();
  }

  @Test
  public void doesSupport_boundClient() throws Exception {
    KmsClient client = AzureKeyVaultClient.create(FAKE_CREDENTIAL, KEY_URI);
    assertThat(client.doesSupport(KEY_URI)).isTrue();
    assertThat(client.doesSupport(OTHER_KEY_URI)).isFalse();
  }

  @Test
  public void create_keyUriWithWrongPrefix_fails() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> AzureKeyVaultClient.create(FAKE_CREDENTIAL, "aws-kms://nope"));
  }

  @Test
  public void getKeyIdentifier_valid() throws Exception {
    assertThat(AzureKeyVaultClient.getKeyIdentifier(KEY_URI))
        .isEqualTo(
            "https://myhsm.managedhsm.azure.net/keys/mykey/00112233445566778899aabbccddeeff");
  }

  @Test
  public void getKeyIdentifier_invalid() throws Exception {
    assertThrows(
        GeneralSecurityException.class, () -> AzureKeyVaultClient.getKeyIdentifier("https://x"));
    assertThrows(
        GeneralSecurityException.class, () -> AzureKeyVaultClient.getKeyIdentifier("azure-kv://"));
    // Host present but missing the /keys/<name> path.
    assertThrows(
        GeneralSecurityException.class,
        () -> AzureKeyVaultClient.getKeyIdentifier("azure-kv://myhsm.managedhsm.azure.net"));
    assertThrows(
        GeneralSecurityException.class,
        () -> AzureKeyVaultClient.getKeyIdentifier("azure-kv://myhsm.managedhsm.azure.net/keys/"));
  }

  @Test
  public void getKeyIdentifier_validWithoutVersion() throws Exception {
    assertThat(
            AzureKeyVaultClient.getKeyIdentifier("azure-kv://myhsm.managedhsm.azure.net/keys/mykey"))
        .isEqualTo("https://myhsm.managedhsm.azure.net/keys/mykey");
  }

  @Test
  public void withCredentials_unsupported() throws Exception {
    KmsClient client = AzureKeyVaultClient.create(FAKE_CREDENTIAL);
    assertThrows(UnsupportedOperationException.class, () -> client.withCredentials("/path"));
  }

  @Test
  public void getAead_boundClientWrongUri_fails() throws Exception {
    KmsClient client = AzureKeyVaultClient.create(FAKE_CREDENTIAL, KEY_URI);
    assertThrows(GeneralSecurityException.class, () -> client.getAead(OTHER_KEY_URI));
  }

  @Test
  public void getAead_withoutCredentials_fails() throws Exception {
    KmsClient client = AzureKeyVaultClient.create(null);
    assertThrows(GeneralSecurityException.class, () -> client.getAead(KEY_URI));
  }

  @Test
  public void getAead_returnsAead() throws Exception {
    KmsClient client = AzureKeyVaultClient.create(FAKE_CREDENTIAL, KEY_URI);
    assertThat(client.getAead(KEY_URI)).isNotNull();
  }

  @Test
  public void register_addsClientToRegistry() throws Exception {
    AzureKeyVaultClient.register(KEY_URI, FAKE_CREDENTIAL);
    assertThat(KmsClients.get(KEY_URI)).isNotNull();
  }
}
