package juloo.keyboard2.ironkeys;

import android.annotation.TargetApi;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

@TargetApi(23)
final class IronKeysSecretKeyBox
{
  private static final String ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore";
  private static final String AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding";
  private static final int AES_KEY_SIZE_BITS = 256;
  private static final byte WRAPPED_VALUE_VERSION = 1;
  private static final int GCM_IV_LENGTH_BYTES = 12;
  private static final int GCM_TAG_LENGTH_BITS = 128;

  byte[] encrypt(String alias, byte[] plaintext)
      throws GeneralSecurityException
  {
    SecretKey secretKey = loadOrCreateSecretKey(alias);
    Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    byte[] iv = cipher.getIV();
    byte[] ciphertext = cipher.doFinal(plaintext);

    byte[] wrappedValue = new byte[1 + iv.length + ciphertext.length];
    wrappedValue[0] = WRAPPED_VALUE_VERSION;
    System.arraycopy(iv, 0, wrappedValue, 1, iv.length);
    System.arraycopy(ciphertext, 0, wrappedValue, 1 + iv.length,
        ciphertext.length);
    return wrappedValue;
  }

  byte[] decrypt(String alias, byte[] wrappedValue)
      throws GeneralSecurityException
  {
    if (wrappedValue.length <= 1 + GCM_IV_LENGTH_BYTES ||
        wrappedValue[0] != WRAPPED_VALUE_VERSION)
      throw new GeneralSecurityException("Unsupported encrypted key snapshot.");

    SecretKey secretKey = loadExistingSecretKey(alias);
    if (secretKey == null)
      throw new IronKeysMissingWrappingKeyException();

    byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
    System.arraycopy(wrappedValue, 1, iv, 0, iv.length);
    byte[] ciphertext = new byte[wrappedValue.length - 1 - iv.length];
    System.arraycopy(wrappedValue, 1 + iv.length, ciphertext, 0,
        ciphertext.length);

    Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
    cipher.init(Cipher.DECRYPT_MODE, secretKey,
        new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
    return cipher.doFinal(ciphertext);
  }

  private SecretKey loadOrCreateSecretKey(String alias)
      throws GeneralSecurityException
  {
    SecretKey existingKey = loadExistingSecretKey(alias);
    if (existingKey != null)
      return existingKey;

    KeyGenerator keyGenerator = KeyGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE_PROVIDER);
    KeyGenParameterSpec parameterSpec = new KeyGenParameterSpec.Builder(
        alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(AES_KEY_SIZE_BITS)
        .setUserAuthenticationRequired(false)
        .build();
    keyGenerator.init(parameterSpec);
    return keyGenerator.generateKey();
  }

  private SecretKey loadExistingSecretKey(String alias)
      throws GeneralSecurityException
  {
    KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER);
    try
    {
      keyStore.load(null);
    }
    catch (IOException e)
    {
      throw new GeneralSecurityException("Unable to load Android Keystore.", e);
    }
    return (SecretKey)keyStore.getKey(alias, null);
  }
}
