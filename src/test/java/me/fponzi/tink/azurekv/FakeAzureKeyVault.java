// Copyright 2024 Federico Ponzi
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

import com.azure.security.keyvault.keys.cryptography.models.DecryptParameters;
import com.azure.security.keyvault.keys.cryptography.models.DecryptResult;
import com.azure.security.keyvault.keys.cryptography.models.EncryptParameters;
import com.azure.security.keyvault.keys.cryptography.models.EncryptResult;
import com.azure.security.keyvault.keys.cryptography.models.EncryptionAlgorithm;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.subtle.Random;
import java.security.GeneralSecurityException;

/**
 * A fake {@link KeyVaultCrypto} that emulates a single Azure Key Vault key using a local Tink
 * AES-GCM {@link Aead}.
 *
 * <p>It returns a realistically-sized IV and authentication tag (which it ignores on decrypt) so
 * that {@link AzureKeyVaultAead}'s framing logic is fully exercised. The actual
 * confidentiality/authentication is provided by the underlying Tink AEAD, so associated-data and
 * wrong-key mismatches behave like the real service.
 */
final class FakeAzureKeyVault implements KeyVaultCrypto {
  private static final String KEY_ID = "https://fake.vault.azure.net/keys/fake/1";
  private final Aead aead;

  FakeAzureKeyVault() throws GeneralSecurityException {
    this.aead =
        KeysetHandle.generateNew(KeyTemplates.get("AES128_GCM"))
            .getPrimitive(RegistryConfiguration.get(), Aead.class);
  }

  @Override
  public EncryptResult encrypt(EncryptParameters parameters) {
    byte[] aad = parameters.getAdditionalAuthenticatedData();
    byte[] ciphertext;
    try {
      ciphertext = aead.encrypt(parameters.getPlainText(), aad == null ? new byte[0] : aad);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
    return new EncryptResult(
        ciphertext, EncryptionAlgorithm.A256GCM, KEY_ID, Random.randBytes(12), Random.randBytes(16),
        aad);
  }

  @Override
  public DecryptResult decrypt(DecryptParameters parameters) {
    byte[] aad = parameters.getAdditionalAuthenticatedData();
    byte[] plaintext;
    try {
      plaintext = aead.decrypt(parameters.getCipherText(), aad == null ? new byte[0] : aad);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
    return new DecryptResult(plaintext, EncryptionAlgorithm.A256GCM, KEY_ID);
  }
}
