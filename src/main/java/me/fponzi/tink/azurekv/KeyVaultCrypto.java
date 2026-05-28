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

import com.azure.security.keyvault.keys.cryptography.models.DecryptParameters;
import com.azure.security.keyvault.keys.cryptography.models.DecryptResult;
import com.azure.security.keyvault.keys.cryptography.models.EncryptParameters;
import com.azure.security.keyvault.keys.cryptography.models.EncryptResult;

/**
 * A minimal seam over Azure Key Vault cryptographic operations.
 *
 * <p>Azure's {@code CryptographyClient} is {@code final} and cannot be subclassed, so this
 * interface exists purely to keep {@link AzureKeyVaultAead} testable with a fake. Production code
 * uses {@link CryptographyClientCrypto}.
 */
interface KeyVaultCrypto {
  EncryptResult encrypt(EncryptParameters parameters);

  DecryptResult decrypt(DecryptParameters parameters);
}
