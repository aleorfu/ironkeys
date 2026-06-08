package juloo.keyboard2.ironkeys;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class IronKeysPublicKeyDirectoryCodec
{
  private static final String ENTRY_SEPARATOR = "\n";
  private static final String FIELD_SEPARATOR = "\\|";
  private static final String FIELD_JOIN_SEPARATOR = "|";
  private static final String STORAGE_VERSION = "v1";
  private static final int STORAGE_FIELD_COUNT = 8;
  private static final int VERSION_INDEX = 0;
  private static final int NAME_INDEX = 1;
  private static final int KEY_ID_INDEX = 2;
  private static final int ALGORITHM_INDEX = 3;
  private static final int EC_PUBLIC_KEY_INDEX = 4;
  private static final int MLKEM_PUBLIC_KEY_INDEX = 5;
  private static final int FINGERPRINT_INDEX = 6;
  private static final int ADDED_AT_INDEX = 7;

  private static final String BEGIN_MARKER =
      "-----BEGIN IRONKEYS PUBLIC KEY DIRECTORY-----";
  private static final String END_MARKER =
      "-----END IRONKEYS PUBLIC KEY DIRECTORY-----";
  private static final String BACKUP_VERSION = "1";
  private static final int MAX_BACKUP_BLOCK_LENGTH_CHARS = 1024 * 1024;

  public String encodeBackup(List<IronKeysPublicKey> publicKeys)
  {
    String encodedKeys = IronKeysBase64.encodeUrlString(encodeStoredKeys(publicKeys));
    StringBuilder builder = new StringBuilder();
    builder.append(BEGIN_MARKER).append('\n');
    builder.append("version: ").append(BACKUP_VERSION).append('\n');
    builder.append("keys: ").append(encodedKeys).append('\n');
    builder.append(END_MARKER);
    return builder.toString();
  }

  public List<IronKeysPublicKey> decodeBackup(String rawBackup)
  {
    String block = extractBlock(rawBackup);
    if (block == null || block.length() > MAX_BACKUP_BLOCK_LENGTH_CHARS)
      return null;

    Map<String, String> values = new LinkedHashMap<String, String>();
    String[] lines = block.split("\\r?\\n");
    for (String line : lines)
    {
      Entry entry = toEntry(line.trim());
      if (entry != null)
        values.put(entry.key, entry.value);
    }
    if (!BACKUP_VERSION.equals(values.get("version")) ||
        !values.containsKey("keys"))
      return null;

    try
    {
      return decodeStoredKeys(IronKeysBase64.decodeUrlString(values.get("keys")));
    }
    catch (IllegalArgumentException e)
    {
      return null;
    }
  }

  String encodeStoredKeys(List<IronKeysPublicKey> publicKeys)
  {
    List<String> encodedKeys = new ArrayList<String>();
    for (IronKeysPublicKey publicKey : publicKeys)
    {
      encodedKeys.add(encodeFields(
          STORAGE_VERSION,
          publicKey.name,
          publicKey.keyId,
          publicKey.algorithm,
          publicKey.ecPublicKeyBase64,
          publicKey.mlKemPublicKeyBase64,
          publicKey.fingerprint,
          Long.toString(publicKey.addedAtEpochMillis)));
    }
    return join(encodedKeys, ENTRY_SEPARATOR);
  }

  List<IronKeysPublicKey> decodeStoredKeys(String rawValue)
  {
    List<IronKeysPublicKey> publicKeys = new ArrayList<IronKeysPublicKey>();
    if (rawValue == null || rawValue.trim().isEmpty())
      return publicKeys;

    String[] lines = rawValue.split("\\r?\\n");
    for (String line : lines)
    {
      String trimmed = line.trim();
      if (trimmed.isEmpty())
        continue;
      IronKeysPublicKey publicKey = decodeStoredKeyFields(decodeFields(trimmed));
      if (publicKey == null)
        return null;
      publicKeys.add(publicKey);
    }
    return publicKeys;
  }

  private IronKeysPublicKey decodeStoredKeyFields(List<String> fields)
  {
    if (fields.size() != STORAGE_FIELD_COUNT ||
        !STORAGE_VERSION.equals(fields.get(VERSION_INDEX)))
      return null;

    String name = sanitizeValue(fields.get(NAME_INDEX));
    String keyId = fields.get(KEY_ID_INDEX).trim();
    String algorithm = fields.get(ALGORITHM_INDEX).trim();
    String ecPublicKeyBase64 = fields.get(EC_PUBLIC_KEY_INDEX).trim();
    String mlKemPublicKeyBase64 = fields.get(MLKEM_PUBLIC_KEY_INDEX).trim();
    String fingerprint = fields.get(FINGERPRINT_INDEX).trim();
    Long addedAtEpochMillis = parseLong(fields.get(ADDED_AT_INDEX));
    if (name.isEmpty() || keyId.isEmpty() || ecPublicKeyBase64.isEmpty() ||
        mlKemPublicKeyBase64.isEmpty() || fingerprint.isEmpty() ||
        addedAtEpochMillis == null || addedAtEpochMillis.longValue() < 0)
      return null;

    IronKeysPublicKeyValidator.ValidationResult validation =
        IronKeysPublicKeyValidator.validate(keyId, algorithm, ecPublicKeyBase64,
            mlKemPublicKeyBase64, fingerprint);
    if (validation.status !=
        IronKeysPublicKeyValidator.ValidationResult.Status.SUCCESS)
      return null;

    return new IronKeysPublicKey(
        validation.keyId,
        name,
        validation.keyId,
        algorithm,
        validation.normalizedEcPublicKeyBase64,
        validation.normalizedMlKemPublicKeyBase64,
        validation.fingerprint,
        addedAtEpochMillis.longValue());
  }

  private static String extractBlock(String rawBackup)
  {
    if (rawBackup == null)
      return null;
    int startIndex = rawBackup.indexOf(BEGIN_MARKER);
    if (startIndex < 0)
      return null;
    int contentStart = startIndex + BEGIN_MARKER.length();
    int endIndex = rawBackup.indexOf(END_MARKER, contentStart);
    if (endIndex < 0)
      return null;
    return rawBackup.substring(contentStart, endIndex).trim();
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

  private String encodeFields(String... fields)
  {
    List<String> encodedFields = new ArrayList<String>();
    for (String field : fields)
      encodedFields.add(IronKeysBase64.encodeUrlString(
          field == null ? "" : field));
    return join(encodedFields, FIELD_JOIN_SEPARATOR);
  }

  private List<String> decodeFields(String encodedValue)
  {
    List<String> fields = new ArrayList<String>();
    try
    {
      String[] tokens = encodedValue.split(FIELD_SEPARATOR, -1);
      for (String token : tokens)
        fields.add(IronKeysBase64.decodeUrlString(token));
    }
    catch (IllegalArgumentException e)
    {
      fields.clear();
    }
    return fields;
  }

  private static String sanitizeValue(String value)
  {
    if (value == null)
      return "";
    return value.replace('\n', ' ').replace('\r', ' ').trim();
  }

  private static Long parseLong(String value)
  {
    try
    {
      return Long.valueOf(value);
    }
    catch (NumberFormatException e)
    {
      return null;
    }
  }

  private static String join(List<String> values, String separator)
  {
    StringBuilder builder = new StringBuilder();
    for (int i = 0; i < values.size(); i++)
    {
      if (i > 0)
        builder.append(separator);
      builder.append(values.get(i));
    }
    return builder.toString();
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
}
