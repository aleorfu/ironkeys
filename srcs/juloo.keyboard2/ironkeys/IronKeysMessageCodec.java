package juloo.keyboard2.ironkeys;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public final class IronKeysMessageCodec
{
  private static final String CURRENT_VERSION = "2";
  private static final String COMPACT_PREFIX = "IKM" + CURRENT_VERSION + ":";
  private static final int MAX_MESSAGE_BLOCK_LENGTH_CHARS = 2 * 1024 * 1024;
  private static final int MAX_COMPACT_FIELD_BYTES = 0xffff;
  private static final int MAX_COMPACT_RECIPIENTS = 1024;

  public String encode(IronKeysMessage message)
  {
    return COMPACT_PREFIX + IronKeysBase64.encodeUrl(
        encodeCompactPayload(message));
  }

  public DecodeResult decode(String rawMessage)
  {
    String compactPayload = extractCompactPayload(rawMessage);
    if (compactPayload != null)
      return decodeCompactPayload(compactPayload);
    return DecodeResult.invalid();
  }

  private static byte[] encodeCompactPayload(IronKeysMessage message)
  {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    writeCompactString(output, message.senderKeyId);
    writeCompactBytes(output,
        IronKeysBase64.decode(message.senderEcPublicKeyBase64));
    writeCompactBytes(output,
        IronKeysBase64.decode(message.senderMlKemPublicKeyBase64));
    writeCompactBytes(output, message.messageNonce);
    writeCompactBytes(output, message.messageCiphertext);
    if (message.recipients.size() > MAX_COMPACT_RECIPIENTS)
      throw new IllegalArgumentException("Too many compact recipients.");
    writeUnsignedShort(output, message.recipients.size());
    for (RecipientEnvelope recipient : message.recipients)
    {
      writeCompactString(output, recipient.recipientKeyId);
      writeCompactBytes(output, recipient.mlKemEncapsulation);
      writeCompactBytes(output, recipient.wrapNonce);
      writeCompactBytes(output, recipient.wrappedMessageKey);
    }
    return output.toByteArray();
  }

  private static DecodeResult decodeCompactPayload(String encodedPayload)
  {
    try
    {
      CompactReader reader =
          new CompactReader(IronKeysBase64.decodeUrl(encodedPayload));
      String senderKeyId = reader.readString();
      byte[] senderEcPublicKey = reader.readBytes();
      byte[] senderMlKemPublicKey = reader.readBytes();
      byte[] messageNonce = reader.readBytes();
      byte[] messageCiphertext = reader.readBytes();
      int recipientCount = reader.readUnsignedShort();
      if (senderKeyId.trim().isEmpty() || senderEcPublicKey.length == 0 ||
          senderMlKemPublicKey.length == 0 || messageNonce.length == 0 ||
          messageCiphertext.length == 0 || recipientCount <= 0 ||
          recipientCount > MAX_COMPACT_RECIPIENTS)
        return DecodeResult.invalid();

      List<RecipientEnvelope> recipients =
          new ArrayList<RecipientEnvelope>();
      for (int i = 0; i < recipientCount; i++)
      {
        String recipientKeyId = reader.readString();
        byte[] mlKemEncapsulation = reader.readBytes();
        byte[] wrapNonce = reader.readBytes();
        byte[] wrappedMessageKey = reader.readBytes();
        if (recipientKeyId.trim().isEmpty() ||
            mlKemEncapsulation.length == 0 || wrapNonce.length == 0 ||
            wrappedMessageKey.length == 0)
          return DecodeResult.invalid();
        recipients.add(new RecipientEnvelope(recipientKeyId,
            mlKemEncapsulation, wrapNonce, wrappedMessageKey));
      }
      if (reader.hasRemaining())
        return DecodeResult.invalid();

      String senderEcPublicKeyBase64 = IronKeysBase64.encode(senderEcPublicKey);
      String senderMlKemPublicKeyBase64 =
          IronKeysBase64.encode(senderMlKemPublicKey);
      String senderFingerprint =
          IronKeysPrivateKeyMetadata.fingerprintForPublicKeyBundle(
              senderEcPublicKey, senderMlKemPublicKey);
      IronKeysPublicKeyValidator.ValidationResult validation =
          IronKeysPublicKeyValidator.validate(senderKeyId,
              IronKeysPublicKeyValidator.SUPPORTED_ALGORITHM,
              senderEcPublicKeyBase64, senderMlKemPublicKeyBase64,
              senderFingerprint);
      if (validation.status !=
          IronKeysPublicKeyValidator.ValidationResult.Status.SUCCESS)
        return DecodeResult.invalid();

      return DecodeResult.success(new IronKeysMessage(
          validation.keyId,
          validation.fingerprint,
          validation.normalizedEcPublicKeyBase64,
          validation.normalizedMlKemPublicKeyBase64,
          messageNonce,
          messageCiphertext,
          recipients));
    }
    catch (IllegalArgumentException e)
    {
      return DecodeResult.invalid();
    }
  }

  private static String extractCompactPayload(String rawMessage)
  {
    if (rawMessage == null)
      return null;
    int startIndex = rawMessage.indexOf(COMPACT_PREFIX);
    if (startIndex < 0)
      return null;
    int payloadStart = startIndex + COMPACT_PREFIX.length();
    int payloadEnd = payloadStart;
    while (payloadEnd < rawMessage.length() &&
        isBase64UrlChar(rawMessage.charAt(payloadEnd)))
      payloadEnd++;
    if (payloadEnd == payloadStart)
      return null;
    String payload = rawMessage.substring(payloadStart, payloadEnd);
    return payload.length() > MAX_MESSAGE_BLOCK_LENGTH_CHARS ? null : payload;
  }

  private static boolean isBase64UrlChar(char c)
  {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9') || c == '_' || c == '-';
  }

  private static void writeCompactString(ByteArrayOutputStream output,
      String value)
  {
    writeCompactBytes(output,
        value == null ? new byte[0] : value.getBytes(StandardCharsets.UTF_8));
  }

  private static void writeCompactBytes(ByteArrayOutputStream output,
      byte[] value)
  {
    byte[] bytes = value == null ? new byte[0] : value;
    writeUnsignedShort(output, bytes.length);
    output.write(bytes, 0, bytes.length);
  }

  private static void writeUnsignedShort(ByteArrayOutputStream output,
      int value)
  {
    if (value < 0 || value > MAX_COMPACT_FIELD_BYTES)
      throw new IllegalArgumentException("Compact field is too large.");
    output.write((value >>> 8) & 0xff);
    output.write(value & 0xff);
  }

  private static final class CompactReader
  {
    private final byte[] _data;
    private int _offset;

    CompactReader(byte[] data)
    {
      _data = data == null ? new byte[0] : data;
      _offset = 0;
    }

    boolean hasRemaining()
    {
      return _offset < _data.length;
    }

    int readUnsignedShort()
    {
      if (_offset + 2 > _data.length)
        throw new IllegalArgumentException("Truncated compact message.");
      int value = ((_data[_offset] & 0xff) << 8) |
          (_data[_offset + 1] & 0xff);
      _offset += 2;
      return value;
    }

    byte[] readBytes()
    {
      int length = readUnsignedShort();
      if (_offset + length > _data.length)
        throw new IllegalArgumentException("Truncated compact field.");
      byte[] value = new byte[length];
      System.arraycopy(_data, _offset, value, 0, length);
      _offset += length;
      return value;
    }

    String readString()
    {
      return new String(readBytes(), StandardCharsets.UTF_8);
    }
  }

  public static final class IronKeysMessage
  {
    public final String senderKeyId;
    public final String senderFingerprint;
    public final String senderEcPublicKeyBase64;
    public final String senderMlKemPublicKeyBase64;
    public final byte[] messageNonce;
    public final byte[] messageCiphertext;
    public final List<RecipientEnvelope> recipients;

    public IronKeysMessage(String senderKeyId, String senderFingerprint,
        String senderEcPublicKeyBase64, String senderMlKemPublicKeyBase64,
        byte[] messageNonce, byte[] messageCiphertext,
        List<RecipientEnvelope> recipients)
    {
      this.senderKeyId = senderKeyId;
      this.senderFingerprint = senderFingerprint;
      this.senderEcPublicKeyBase64 = senderEcPublicKeyBase64;
      this.senderMlKemPublicKeyBase64 = senderMlKemPublicKeyBase64;
      this.messageNonce = messageNonce;
      this.messageCiphertext = messageCiphertext;
      this.recipients = recipients;
    }
  }

  public static final class RecipientEnvelope
  {
    public final String recipientKeyId;
    public final byte[] mlKemEncapsulation;
    public final byte[] wrapNonce;
    public final byte[] wrappedMessageKey;

    public RecipientEnvelope(String recipientKeyId, byte[] mlKemEncapsulation,
        byte[] wrapNonce, byte[] wrappedMessageKey)
    {
      this.recipientKeyId = recipientKeyId;
      this.mlKemEncapsulation = mlKemEncapsulation;
      this.wrapNonce = wrapNonce;
      this.wrappedMessageKey = wrappedMessageKey;
    }
  }

  public static final class DecodeResult
  {
    public static enum Status
    {
      SUCCESS,
      INVALID
    }

    public final Status status;
    public final IronKeysMessage message;

    private DecodeResult(Status status, IronKeysMessage message)
    {
      this.status = status;
      this.message = message;
    }

    static DecodeResult success(IronKeysMessage message)
    {
      return new DecodeResult(Status.SUCCESS, message);
    }

    static DecodeResult invalid()
    {
      return new DecodeResult(Status.INVALID, null);
    }
  }
}
