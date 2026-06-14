package juloo.keyboard2.ironkeys;

import java.util.Arrays;
import org.junit.Test;
import static org.junit.Assert.*;

public class IronKeysMessageCipherTest
{
  private final IronKeysPrivateKeyGenerator _generator =
      new IronKeysPrivateKeyGenerator();
  private final IronKeysMessageCipher _cipher = new IronKeysMessageCipher();
  private final IronKeysMessageCodec _codec = new IronKeysMessageCodec();

  @Test
  public void encrypts_for_single_recipient() throws Exception
  {
    IronKeysPrivateKey sender = _generator.generate("Sender");
    IronKeysPrivateKey recipient = _generator.generate("Recipient");

    String encoded = _cipher.encrypt("group message", sender,
        Arrays.asList(publicKey(recipient, 10)));

    assertEquals("group message", _cipher.decrypt(encoded, recipient));
  }

  @Test(expected = java.security.GeneralSecurityException.class)
  public void refuses_to_encrypt_for_multiple_recipients() throws Exception
  {
    IronKeysPrivateKey sender = _generator.generate("Sender");
    IronKeysPrivateKey first = _generator.generate("First");
    IronKeysPrivateKey second = _generator.generate("Second");

    _cipher.encrypt("group message", sender,
        Arrays.asList(publicKey(first, 10), publicKey(second, 20)));
  }

  @Test
  public void does_not_include_sender_as_implicit_recipient() throws Exception
  {
    IronKeysPrivateKey sender = _generator.generate("Sender");
    IronKeysPrivateKey recipient = _generator.generate("Recipient");

    String encoded = _cipher.encrypt("self readable", sender,
        Arrays.asList(publicKey(recipient, 10)));

    try
    {
      _cipher.decrypt(encoded, sender);
      fail("Sender should not decrypt unless its public key was selected.");
    }
    catch (java.security.GeneralSecurityException expected)
    {
    }
  }

  @Test
  public void sender_can_decrypt_when_selected_as_public_recipient()
      throws Exception
  {
    IronKeysPrivateKey sender = _generator.generate("Sender");

    String encoded = _cipher.encrypt("dedupe", sender,
        Arrays.asList(publicKey(sender, 10)));

    IronKeysMessageCodec.DecodeResult decoded = _codec.decode(encoded);

    assertEquals(IronKeysMessageCodec.DecodeResult.Status.SUCCESS,
        decoded.status);
    assertEquals(1, decoded.message.recipients.size());
    assertEquals(sender.keyId,
        decoded.message.recipients.get(0).recipientKeyId);
    assertEquals("dedupe", _cipher.decrypt(encoded, sender));
  }

  @Test(expected = java.security.GeneralSecurityException.class)
  public void refuses_to_encrypt_without_public_recipients()
      throws Exception
  {
    IronKeysPrivateKey sender = _generator.generate("Sender");

    _cipher.encrypt("missing recipients", sender,
        Arrays.<IronKeysPublicKey>asList());
  }

  @Test(expected = java.security.GeneralSecurityException.class)
  public void refuses_to_encrypt_messages_longer_than_32_characters()
      throws Exception
  {
    IronKeysPrivateKey sender = _generator.generate("Sender");
    IronKeysPrivateKey recipient = _generator.generate("Recipient");

    _cipher.encrypt("123456789012345678901234567890123", sender,
        Arrays.asList(publicKey(recipient, 10)));
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
