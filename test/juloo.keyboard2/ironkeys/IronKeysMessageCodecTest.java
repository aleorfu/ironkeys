package juloo.keyboard2.ironkeys;

import java.util.Arrays;
import org.junit.Test;
import static org.junit.Assert.*;

public class IronKeysMessageCodecTest
{
  private final IronKeysPrivateKeyGenerator _generator =
      new IronKeysPrivateKeyGenerator();
  private final IronKeysMessageCipher _cipher = new IronKeysMessageCipher();
  private final IronKeysMessageCodec _codec = new IronKeysMessageCodec();

  @Test
  public void message_codec_round_trip() throws Exception
  {
    IronKeysPrivateKey sender = _generator.generate("Sender");
    IronKeysPrivateKey recipient = _generator.generate("Recipient");

    String encoded = _cipher.encrypt("hello",
        sender, Arrays.asList(publicKey(recipient, 20)));

    assertTrue(encoded.startsWith("IKM2:"));
    assertFalse(encoded.contains("suite:"));
    assertFalse(encoded.contains("sender-fingerprint:"));
    assertFalse(encoded.contains("sender-mlkem-public-key:"));
    assertFalse(encoded.contains("message-ciphertext:"));

    IronKeysMessageCodec.DecodeResult decoded = _codec.decode(encoded);

    assertEquals(IronKeysMessageCodec.DecodeResult.Status.SUCCESS,
        decoded.status);
    assertEquals(sender.keyId, decoded.message.senderKeyId);
    assertEquals(sender.fingerprint, decoded.message.senderFingerprint);
    assertEquals(sender.ecPublicKeyBase64,
        decoded.message.senderEcPublicKeyBase64);
    assertEquals(sender.mlKemPublicKeyBase64,
        decoded.message.senderMlKemPublicKeyBase64);
    assertEquals(1, decoded.message.recipients.size());
  }

  @Test
  public void message_codec_rejects_malformed_text()
  {
    IronKeysMessageCodec.DecodeResult decoded =
        _codec.decode("not an ironkeys message");

    assertEquals(IronKeysMessageCodec.DecodeResult.Status.INVALID,
        decoded.status);
  }

  @Test
  public void message_codec_rejects_tampered_compact_message()
      throws Exception
  {
    IronKeysPrivateKey sender = _generator.generate("Sender");
    IronKeysPrivateKey recipient = _generator.generate("Recipient");

    String encoded = _cipher.encrypt("hello",
        sender, Arrays.asList(publicKey(recipient, 20)));

    IronKeysMessageCodec.DecodeResult decoded = _codec.decode(
        encoded.substring(0, encoded.length() - 1) + "*");

    assertEquals(IronKeysMessageCodec.DecodeResult.Status.INVALID,
        decoded.status);
  }

  @Test
  public void message_codec_rejects_mismatched_sender_key_id()
      throws Exception
  {
    IronKeysPrivateKey sender = _generator.generate("Sender");
    IronKeysPrivateKey recipient = _generator.generate("Recipient");

    IronKeysMessageCodec.DecodeResult original = _codec.decode(_cipher.encrypt(
        "hello", sender, Arrays.asList(publicKey(recipient, 20))));
    assertEquals(IronKeysMessageCodec.DecodeResult.Status.SUCCESS,
        original.status);

    String encoded = _codec.encode(new IronKeysMessageCodec.IronKeysMessage(
        "ik_tamperedSender",
        original.message.senderFingerprint,
        original.message.senderEcPublicKeyBase64,
        original.message.senderMlKemPublicKeyBase64,
        original.message.messageNonce,
        original.message.messageCiphertext,
        original.message.recipients));

    IronKeysMessageCodec.DecodeResult decoded = _codec.decode(encoded);

    assertEquals(IronKeysMessageCodec.DecodeResult.Status.INVALID,
        decoded.status);
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
