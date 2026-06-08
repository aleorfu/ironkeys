package juloo.keyboard2.ironkeys;

import java.util.LinkedHashMap;
import java.util.Map;

public final class IronKeysPublicKeyShareCodec
{
  private static final String BEGIN_MARKER =
      "-----BEGIN IRONKEYS PUBLIC KEY-----";
  private static final String END_MARKER =
      "-----END IRONKEYS PUBLIC KEY-----";
  private static final String LEGACY_VERSION = "1";
  private static final String CURRENT_VERSION = "2";
  private static final int MAX_SHARE_BLOCK_LENGTH_CHARS = 20 * 1024;
  private static final int MAX_PUBLIC_KEY_FIELD_LENGTH_CHARS = 8192;

  public String encode(IronKeysPrivateKey privateKey)
  {
    return encode(
        privateKey.name,
        privateKey.keyId,
        privateKey.algorithm,
        privateKey.ecPublicKeyBase64,
        privateKey.mlKemPublicKeyBase64,
        privateKey.fingerprint);
  }

  public String encode(IronKeysPublicKey publicKey)
  {
    return encode(
        publicKey.name,
        publicKey.keyId,
        publicKey.algorithm,
        publicKey.ecPublicKeyBase64,
        publicKey.mlKemPublicKeyBase64,
        publicKey.fingerprint);
  }

  private String encode(String name, String keyId, String algorithm,
      String ecPublicKeyBase64, String mlKemPublicKeyBase64,
      String fingerprint)
  {
    StringBuilder builder = new StringBuilder();
    builder.append(BEGIN_MARKER).append('\n');
    builder.append("version: ").append(CURRENT_VERSION).append('\n');
    builder.append("name: ").append(sanitizeValue(name)).append('\n');
    builder.append("key-id: ").append(keyId).append('\n');
    builder.append("suite: ").append(algorithm).append('\n');
    builder.append("fingerprint: ").append(fingerprint).append('\n');
    builder.append("ec-public-key: ").append(ecPublicKeyBase64).append('\n');
    builder.append("mlkem-public-key: ").append(mlKemPublicKeyBase64)
        .append('\n');
    builder.append(END_MARKER);
    return builder.toString();
  }

  public DecodeResult decode(String rawShareText)
  {
    String block = extractBlock(rawShareText);
    if (block == null || block.length() > MAX_SHARE_BLOCK_LENGTH_CHARS)
      return DecodeResult.invalid();

    Map<String, String> values = new LinkedHashMap<String, String>();
    String[] lines = block.split("\\r?\\n");
    for (String line : lines)
    {
      Entry entry = toEntry(line.trim());
      if (entry != null)
        values.put(entry.key, entry.value);
    }

    String version = values.get("version");
    if (LEGACY_VERSION.equals(version))
      return DecodeResult.legacyUnsupported();
    if (!CURRENT_VERSION.equals(version))
      return DecodeResult.invalid();

    String name = value(values, "name").trim();
    String keyId = value(values, "key-id").trim();
    String algorithm = value(values, "suite").trim();
    String fingerprint = value(values, "fingerprint").trim();
    String ecPublicKeyBase64 = value(values, "ec-public-key").trim();
    String mlKemPublicKeyBase64 = value(values, "mlkem-public-key").trim();
    if (name.isEmpty() || keyId.isEmpty() || fingerprint.isEmpty() ||
        ecPublicKeyBase64.isEmpty() || mlKemPublicKeyBase64.isEmpty())
      return DecodeResult.invalid();
    if (ecPublicKeyBase64.length() > MAX_PUBLIC_KEY_FIELD_LENGTH_CHARS ||
        mlKemPublicKeyBase64.length() > MAX_PUBLIC_KEY_FIELD_LENGTH_CHARS)
      return DecodeResult.invalid();

    IronKeysPublicKeyValidator.ValidationResult validation =
        IronKeysPublicKeyValidator.validate(keyId, algorithm, ecPublicKeyBase64,
            mlKemPublicKeyBase64, fingerprint);
    switch (validation.status)
    {
      case SUCCESS:
        return DecodeResult.success(new ParsedPublicKeyShare(
            sanitizeValue(name),
            validation.keyId,
            algorithm,
            validation.normalizedEcPublicKeyBase64,
            validation.normalizedMlKemPublicKeyBase64,
            validation.fingerprint));
      case LEGACY_UNSUPPORTED:
        return DecodeResult.legacyUnsupported();
      case UNSUPPORTED_ALGORITHM:
        return DecodeResult.unsupportedAlgorithm();
      default:
        return DecodeResult.invalid();
    }
  }

  private static String value(Map<String, String> values, String key)
  {
    String value = values.get(key);
    return value == null ? "" : value;
  }

  private static String extractBlock(String rawShareText)
  {
    if (rawShareText == null)
      return null;
    int startIndex = rawShareText.indexOf(BEGIN_MARKER);
    if (startIndex < 0)
      return null;
    int contentStart = startIndex + BEGIN_MARKER.length();
    int endIndex = rawShareText.indexOf(END_MARKER, contentStart);
    if (endIndex < 0)
      return null;
    return rawShareText.substring(contentStart, endIndex).trim();
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

  private static String sanitizeValue(String value)
  {
    if (value == null)
      return "";
    return value.replace('\n', ' ').replace('\r', ' ').trim();
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

  public static final class ParsedPublicKeyShare
  {
    public final String name;
    public final String keyId;
    public final String algorithm;
    public final String ecPublicKeyBase64;
    public final String mlKemPublicKeyBase64;
    public final String fingerprint;

    ParsedPublicKeyShare(String name, String keyId, String algorithm,
        String ecPublicKeyBase64, String mlKemPublicKeyBase64,
        String fingerprint)
    {
      this.name = name;
      this.keyId = keyId;
      this.algorithm = algorithm;
      this.ecPublicKeyBase64 = ecPublicKeyBase64;
      this.mlKemPublicKeyBase64 = mlKemPublicKeyBase64;
      this.fingerprint = fingerprint;
    }
  }

  public static final class DecodeResult
  {
    public static enum Status
    {
      SUCCESS,
      INVALID,
      UNSUPPORTED_ALGORITHM,
      LEGACY_UNSUPPORTED
    }

    public final Status status;
    public final ParsedPublicKeyShare publicKey;

    private DecodeResult(Status status, ParsedPublicKeyShare publicKey)
    {
      this.status = status;
      this.publicKey = publicKey;
    }

    static DecodeResult success(ParsedPublicKeyShare publicKey)
    {
      return new DecodeResult(Status.SUCCESS, publicKey);
    }

    static DecodeResult invalid()
    {
      return new DecodeResult(Status.INVALID, null);
    }

    static DecodeResult unsupportedAlgorithm()
    {
      return new DecodeResult(Status.UNSUPPORTED_ALGORITHM, null);
    }

    static DecodeResult legacyUnsupported()
    {
      return new DecodeResult(Status.LEGACY_UNSUPPORTED, null);
    }
  }
}
