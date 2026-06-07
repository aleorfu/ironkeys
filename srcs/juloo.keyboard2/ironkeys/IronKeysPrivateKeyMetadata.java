package juloo.keyboard2.ironkeys;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

final class IronKeysPrivateKeyMetadata
{
  private static final byte[] BUNDLE_PREFIX =
      "ironkeys-hybrid-v1".getBytes(StandardCharsets.UTF_8);
  private static final int KEY_ID_LENGTH = 16;
  private static final int FINGERPRINT_GROUP_SIZE = 4;

  private IronKeysPrivateKeyMetadata() {}

  static String keyIdForPublicKeyBundle(byte[] encodedEcPublicKey,
      byte[] encodedMlKemPublicKey)
  {
    String encodedDigest = IronKeysBase64.encodeUrl(
        publicKeyBundleDigest(encodedEcPublicKey, encodedMlKemPublicKey));
    return "ik_" + encodedDigest.substring(0, KEY_ID_LENGTH);
  }

  static String fingerprintForPublicKeyBundle(byte[] encodedEcPublicKey,
      byte[] encodedMlKemPublicKey)
  {
    byte[] digest = publicKeyBundleDigest(encodedEcPublicKey,
        encodedMlKemPublicKey);
    StringBuilder hex = new StringBuilder(digest.length * 2);
    for (byte b : digest)
      hex.append(String.format(Locale.US, "%02X", b));

    StringBuilder grouped = new StringBuilder();
    for (int i = 0; i < hex.length(); i += FINGERPRINT_GROUP_SIZE)
    {
      if (i > 0)
        grouped.append(' ');
      grouped.append(hex.substring(i,
          Math.min(i + FINGERPRINT_GROUP_SIZE, hex.length())));
    }
    return grouped.toString();
  }

  private static byte[] publicKeyBundleDigest(byte[] encodedEcPublicKey,
      byte[] encodedMlKemPublicKey)
  {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    output.write(BUNDLE_PREFIX, 0, BUNDLE_PREFIX.length);
    writeLengthPrefixed(output, encodedEcPublicKey);
    writeLengthPrefixed(output, encodedMlKemPublicKey);
    return sha256(output.toByteArray());
  }

  private static void writeLengthPrefixed(ByteArrayOutputStream output,
      byte[] value)
  {
    int length = value.length;
    output.write((length >>> 24) & 0xff);
    output.write((length >>> 16) & 0xff);
    output.write((length >>> 8) & 0xff);
    output.write(length & 0xff);
    output.write(value, 0, value.length);
  }

  private static byte[] sha256(byte[] value)
  {
    try
    {
      return MessageDigest.getInstance("SHA-256").digest(value);
    }
    catch (NoSuchAlgorithmException e)
    {
      throw new IllegalStateException(e);
    }
  }
}
