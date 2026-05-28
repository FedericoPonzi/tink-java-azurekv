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
import com.azure.security.keyvault.keys.cryptography.models.EncryptParameters;
import com.azure.security.keyvault.keys.cryptography.models.EncryptResult;
import com.google.crypto.tink.Aead;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * An {@link Aead} that forwards encryption/decryption to a key in <a
 * href="https://learn.microsoft.com/azure/key-vault/">Azure Key Vault</a> using AES-256-GCM
 * ({@code A256GCM}).
 *
 * <p>AES-GCM is authenticated and supports associated data natively, so this is a true AEAD. The
 * returned ciphertext bundles the Key-Vault-generated IV and authentication tag so that {@link
 * #decrypt} is self-contained.
 *
 * <p>The ciphertext is framed as {@code version(1) || ivLen(1) || iv || tagLen(1) || tag ||
 * ciphertext}. The leading version byte allows the format to evolve without ambiguity.
 */
public final class AzureKeyVaultAead implements Aead {
  private static final byte FORMAT_VERSION = 1;

  private final KeyVaultCrypto crypto;

  private AzureKeyVaultAead(KeyVaultCrypto crypto) {
    this.crypto = crypto;
  }

  static Aead create(KeyVaultCrypto crypto) {
    return new AzureKeyVaultAead(crypto);
  }

  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    byte[] aad = associatedData == null ? new byte[0] : associatedData;
    try {
      EncryptResult result =
          crypto.encrypt(EncryptParameters.createA256GcmParameters(plaintext, aad));
      return frame(result.getIv(), result.getAuthenticationTag(), result.getCipherText());
    } catch (GeneralSecurityException e) {
      throw e;
    } catch (RuntimeException e) {
      throw new GeneralSecurityException("encryption failed", e);
    }
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    byte[] aad = associatedData == null ? new byte[0] : associatedData;
    try {
      byte[][] parts = unframe(ciphertext);
      return crypto
          .decrypt(DecryptParameters.createA256GcmParameters(parts[2], parts[0], parts[1], aad))
          .getPlainText();
    } catch (GeneralSecurityException e) {
      throw e;
    } catch (RuntimeException e) {
      throw new GeneralSecurityException("decryption failed", e);
    }
  }

  /** Serializes a GCM result as {@code version || ivLen || iv || tagLen || tag || ciphertext}. */
  private static byte[] frame(byte[] iv, byte[] tag, byte[] ciphertext)
      throws GeneralSecurityException {
    if (iv.length > 255 || tag.length > 255) {
      throw new GeneralSecurityException("iv or tag too long to serialize");
    }
    byte[] out = new byte[3 + iv.length + tag.length + ciphertext.length];
    int pos = 0;
    out[pos++] = FORMAT_VERSION;
    out[pos++] = (byte) iv.length;
    System.arraycopy(iv, 0, out, pos, iv.length);
    pos += iv.length;
    out[pos++] = (byte) tag.length;
    System.arraycopy(tag, 0, out, pos, tag.length);
    pos += tag.length;
    System.arraycopy(ciphertext, 0, out, pos, ciphertext.length);
    return out;
  }

  /** Inverse of {@link #frame}, returning {@code {iv, tag, ciphertext}}. */
  private static byte[][] unframe(byte[] blob) throws GeneralSecurityException {
    int pos = 0;
    if (blob.length < 1 || blob[pos++] != FORMAT_VERSION) {
      throw new GeneralSecurityException("unsupported ciphertext version");
    }
    if (pos >= blob.length) {
      throw new GeneralSecurityException("malformed ciphertext");
    }
    int ivLen = blob[pos++] & 0xff;
    if (pos + ivLen >= blob.length) {
      throw new GeneralSecurityException("malformed ciphertext");
    }
    byte[] iv = Arrays.copyOfRange(blob, pos, pos + ivLen);
    pos += ivLen;
    int tagLen = blob[pos++] & 0xff;
    if (pos + tagLen > blob.length) {
      throw new GeneralSecurityException("malformed ciphertext");
    }
    byte[] tag = Arrays.copyOfRange(blob, pos, pos + tagLen);
    pos += tagLen;
    byte[] ciphertext = Arrays.copyOfRange(blob, pos, blob.length);
    return new byte[][] {iv, tag, ciphertext};
  }
}
