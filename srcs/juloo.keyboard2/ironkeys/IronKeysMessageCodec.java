package juloo.keyboard2.ironkeys;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class IronKeysMessageCodec
{
  static final String MESSAGE_SUITE =
      "HYBRID_P256_MLKEM768/AES-256-GCM/HKDF-SHA256";

  private static final String BEGIN_MARKER =
      "-----BEGIN IRONKEYS MESSAGE-----";
  private static final String END_MARKER =
      "-----END IRONKEYS MESSAGE-----";
  private static final String LEGACY_VERSION = "1";
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

    String block = extractLegacyBlock(rawMessage);
    if (block == null || block.length() > MAX_MESSAGE_BLOCK_LENGTH_CHARS)
      return DecodeResult.invalid();

    Map<String, String> values = new LinkedHashMap<String, String>();
    List<String> encodedRecipients = new ArrayList<String>();
    String[] lines = block.split("\\r?\\n");
    for (String line : lines)
    {
      Entry entry = toEntry(line.trim());
      if (entry == null)
        continue;
      if ("recipient".equals(entry.key))
        encodedRecipients.add(entry.value);
      else
        values.put(entry.key, entry.value);
    }

    if (!LEGACY_VERSION.equals(values.get("version")) ||
        !MESSAGE_SUITE.equals(values.get("suite")))
      return DecodeResult.invalid();
    return decodeLegacyValues(values, encodedRecipients);
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

  private static DecodeResult decodeLegacyValues(Map<String, String> values,
      List<String> encodedRecipients)
  {
    String senderKeyId = value(values, "sender-key-id").trim();
    String senderFingerprint = value(values, "sender-fingerprint").trim();
    String senderEcPublicKeyBase64 =
        value(values, "sender-ec-public-key").trim();
    String senderMlKemPublicKeyBase64 =
        value(values, "sender-mlkem-public-key").trim();
    byte[] messageNonce = decodeBase64(value(values, "message-nonce").trim());
    byte[] messageCiphertext =
        decodeBase64(value(values, "message-ciphertext").trim());
    if (senderKeyId.isEmpty() || senderFingerprint.isEmpty() ||
        senderEcPublicKeyBase64.isEmpty() ||
        senderMlKemPublicKeyBase64.isEmpty() || messageNonce == null ||
        messageCiphertext == null)
      return DecodeResult.invalid();

    IronKeysPublicKeyValidator.ValidationResult validation =
        IronKeysPublicKeyValidator.validate(senderKeyId,
            IronKeysPublicKeyValidator.SUPPORTED_ALGORITHM,
            senderEcPublicKeyBase64, senderMlKemPublicKeyBase64,
            senderFingerprint);
    if (validation.status !=
        IronKeysPublicKeyValidator.ValidationResult.Status.SUCCESS)
      return DecodeResult.invalid();

    List<RecipientEnvelope> recipients =
        new ArrayList<RecipientEnvelope>();
    for (String encodedRecipient : encodedRecipients)
    {
      RecipientEnvelope recipient = decodeLegacyRecipient(encodedRecipient);
      if (recipient == null)
        return DecodeResult.invalid();
      recipients.add(recipient);
    }
    if (recipients.isEmpty())
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

  private static RecipientEnvelope decodeLegacyRecipient(String encodedRecipient)
  {
    try
    {
      String[] fields = encodedRecipient.split("\\|", -1);
      if (fields.length != 4)
        return null;
      String recipientKeyId = IronKeysBase64.decodeUrlString(fields[0]);
      byte[] mlKemEncapsulation = IronKeysBase64.decodeUrl(fields[1]);
      byte[] wrapNonce = IronKeysBase64.decodeUrl(fields[2]);
      byte[] wrappedMessageKey = IronKeysBase64.decodeUrl(fields[3]);
      if (recipientKeyId.trim().isEmpty() || mlKemEncapsulation.length == 0 ||
          wrapNonce.length == 0 || wrappedMessageKey.length == 0)
        return null;
      return new RecipientEnvelope(recipientKeyId, mlKemEncapsulation,
          wrapNonce, wrappedMessageKey);
    }
    catch (IllegalArgumentException e)
    {
      return null;
    }
  }

  private static byte[] decodeBase64(String value)
  {
    try
    {
      return IronKeysBase64.decode(value);
    }
    catch (IllegalArgumentException e)
    {
      return null;
    }
  }

  private static String value(Map<String, String> values, String key)
  {
    String value = values.get(key);
    return value == null ? "" : value;
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

  private static String extractLegacyBlock(String rawMessage)
  {
    if (rawMessage == null)
      return null;
    int startIndex = rawMessage.indexOf(BEGIN_MARKER);
    if (startIndex < 0)
      return null;
    int contentStart = startIndex + BEGIN_MARKER.length();
    int endIndex = rawMessage.indexOf(END_MARKER, contentStart);
    if (endIndex < 0)
      return null;
    return rawMessage.substring(contentStart, endIndex).trim();
  }

  private static Entry toEntry(String line)
  {
    if (line.isEmpty())
      return null;
    int delimiterIndex = line.indexOf(':');
    if (delimiterIndex <= 0)
      return null;
    return new Entry(
        line.substring(0, delimiterIndex).trim().toLowerCase(java.util.Locale.ROOT),
        line.substring(delimiterIndex + 1).trim());
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

  private static final class Entry
  {
    final String key;
    final String value;

    Entry(String key, String value)
    {
      this.key = key;
      this.value = value;
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
