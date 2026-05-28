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

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.subtle.Random;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link AzureKeyVaultAead}. */
@RunWith(JUnit4.class)
public class AzureKeyVaultAeadTest {

  @BeforeClass
  public static void setUpClass() throws Exception {
    AeadConfig.register();
  }

  @Test
  public void encryptDecryptWithAssociatedData_success() throws Exception {
    Aead aead = AzureKeyVaultAead.create(new FakeAzureKeyVault());
    byte[] message = "hello azure".getBytes();
    byte[] aad = Random.randBytes(20);

    byte[] ciphertext = aead.encrypt(message, aad);

    assertThat(aead.decrypt(ciphertext, aad)).isEqualTo(message);
  }

  @Test
  public void encryptDecryptWithEmptyAssociatedData_success() throws Exception {
    Aead aead = AzureKeyVaultAead.create(new FakeAzureKeyVault());
    byte[] message = "hello azure".getBytes();

    byte[] ciphertext = aead.encrypt(message, new byte[0]);

    assertThat(aead.decrypt(ciphertext, new byte[0])).isEqualTo(message);
  }

  @Test
  public void encryptDecryptWithNullAssociatedData_success() throws Exception {
    Aead aead = AzureKeyVaultAead.create(new FakeAzureKeyVault());
    byte[] message = "hello azure".getBytes();

    byte[] ciphertext = aead.encrypt(message, null);

    assertThat(aead.decrypt(ciphertext, null)).isEqualTo(message);
  }

  @Test
  public void encryptDecryptEmptyPlaintext_success() throws Exception {
    Aead aead = AzureKeyVaultAead.create(new FakeAzureKeyVault());

    byte[] ciphertext = aead.encrypt(new byte[0], new byte[0]);

    assertThat(aead.decrypt(ciphertext, new byte[0])).isEqualTo(new byte[0]);
  }

  @Test
  public void decryptWithWrongAssociatedData_fails() throws Exception {
    Aead aead = AzureKeyVaultAead.create(new FakeAzureKeyVault());
    byte[] ciphertext = aead.encrypt("hi".getBytes(), Random.randBytes(20));

    assertThrows(
        GeneralSecurityException.class, () -> aead.decrypt(ciphertext, Random.randBytes(20)));
  }

  @Test
  public void decryptWithDifferentKey_fails() throws Exception {
    Aead aead1 = AzureKeyVaultAead.create(new FakeAzureKeyVault());
    Aead aead2 = AzureKeyVaultAead.create(new FakeAzureKeyVault());
    byte[] aad = Random.randBytes(20);
    byte[] ciphertext = aead2.encrypt("hi".getBytes(), aad);

    assertThrows(GeneralSecurityException.class, () -> aead1.decrypt(ciphertext, aad));
  }

  @Test
  public void decryptTruncatedCiphertext_fails() throws Exception {
    Aead aead = AzureKeyVaultAead.create(new FakeAzureKeyVault());
    byte[] ciphertext = aead.encrypt("hi".getBytes(), new byte[0]);
    byte[] truncated = Arrays.copyOf(ciphertext, 2);

    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(truncated, new byte[0]));
  }

  @Test
  public void decryptEmptyCiphertext_fails() throws Exception {
    Aead aead = AzureKeyVaultAead.create(new FakeAzureKeyVault());

    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(new byte[0], new byte[0]));
  }

  @Test
  public void decryptModifiedCiphertextBody_fails() throws Exception {
    Aead aead = AzureKeyVaultAead.create(new FakeAzureKeyVault());
    byte[] ciphertext = aead.encrypt("hello azure".getBytes(), new byte[0]);
    // Flip a bit in the last byte, which lies in the ciphertext body, and expect the
    // underlying authenticated decryption to reject it.
    ciphertext[ciphertext.length - 1] ^= 0x01;

    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(ciphertext, new byte[0]));
  }

  @Test
  public void decryptWrongVersionByte_fails() throws Exception {
    Aead aead = AzureKeyVaultAead.create(new FakeAzureKeyVault());
    byte[] ciphertext = aead.encrypt("hi".getBytes(), new byte[0]);
    ciphertext[0] = (byte) 0x7f;

    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(ciphertext, new byte[0]));
  }
}
