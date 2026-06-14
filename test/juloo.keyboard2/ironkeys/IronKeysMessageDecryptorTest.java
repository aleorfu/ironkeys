package juloo.keyboard2.ironkeys;

import java.util.Arrays;
import org.junit.Test;
import static org.junit.Assert.*;

public class IronKeysMessageDecryptorTest
{
  private final IronKeysPrivateKeyGenerator _generator =
      new IronKeysPrivateKeyGenerator();
  private final IronKeysMessageCipher _cipher = new IronKeysMessageCipher();
  private final IronKeysMessageDecryptor _decryptor =
      new IronKeysMessageDecryptor();

  @Test
  public void decrypts_with_matching_private_key() throws Exception
  {
    IronKeysPrivateKey sender = _generator.generate("Sender");
    IronKeysPrivateKey first = _generator.generate("First");
    IronKeysPrivateKey recipient = _generator.generate("Recipient");

    String encoded = _cipher.encrypt("hello", sender,
        Arrays.asList(publicKey(recipient, 20)));

    IronKeysMessageDecryptor.Result result =
        _decryptor.decryptWithAnyPrivateKey(encoded,
            Arrays.asList(first, recipient));

    assertEquals(IronKeysMessageDecryptor.Status.SUCCESS, result.status);
    assertEquals("hello", result.plaintext);
  }

  @Test
  public void rejects_invalid_message()
  {
    IronKeysMessageDecryptor.Result result =
        _decryptor.decryptWithAnyPrivateKey("not an ironkeys message",
            Arrays.<IronKeysPrivateKey>asList());

    assertEquals(IronKeysMessageDecryptor.Status.INVALID_MESSAGE,
        result.status);
  }

  @Test
  public void reports_no_private_keys() throws Exception
  {
    IronKeysPrivateKey sender = _generator.generate("Sender");
    IronKeysPrivateKey recipient = _generator.generate("Recipient");

    String encoded = _cipher.encrypt("hello", sender,
        Arrays.asList(publicKey(recipient, 20)));

    IronKeysMessageDecryptor.Result result =
        _decryptor.decryptWithAnyPrivateKey(encoded,
            Arrays.<IronKeysPrivateKey>asList());

    assertEquals(IronKeysMessageDecryptor.Status.NO_PRIVATE_KEYS,
        result.status);
  }

  @Test
  public void reports_no_matching_private_key() throws Exception
  {
    IronKeysPrivateKey sender = _generator.generate("Sender");
    IronKeysPrivateKey recipient = _generator.generate("Recipient");
    IronKeysPrivateKey other = _generator.generate("Other");

    String encoded = _cipher.encrypt("hello", sender,
        Arrays.asList(publicKey(recipient, 20)));

    IronKeysMessageDecryptor.Result result =
        _decryptor.decryptWithAnyPrivateKey(encoded, Arrays.asList(other));

    assertEquals(IronKeysMessageDecryptor.Status.NO_MATCHING_PRIVATE_KEY,
        result.status);
  }

  private static IronKeysPublicKey publicKey(IronKeysPrivateKey privateKey,
      long addedAtEpochMillis)
  {
    return new IronKeysPublicKey(
        privateKey.keyId,
        privateKey.name,
        privateKey.keyId,
        privateKey.algorithm,
        privateKey.ecPublicKeyBase64,
        privateKey.mlKemPublicKeyBase64,
        privateKey.fingerprint,
        addedAtEpochMillis);
  }
}
