package juloo.keyboard2.ironkeys;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;

public class IronKeysPrivateKeyCodecTest
{
  private final IronKeysPrivateKeyGenerator _generator =
      new IronKeysPrivateKeyGenerator();
  private final IronKeysPrivateKeyCodec _codec = new IronKeysPrivateKeyCodec();

  @Test
  public void backup_round_trip_preserves_selected_key_order() throws Exception
  {
    IronKeysPrivateKey first = _generator.generate("First");
    IronKeysPrivateKey second = _generator.generate("Second");

    List<IronKeysPrivateKey> decoded = _codec.decodeImport(
        _codec.encodeBackup(Arrays.asList(first, second), second.id));

    assertEquals(2, decoded.size());
    assertKeyEquals(second, decoded.get(0));
    assertKeyEquals(first, decoded.get(1));
  }

  @Test
  public void local_keys_round_trip() throws Exception
  {
    IronKeysPrivateKey privateKey = _generator.generate("Local");

    List<IronKeysPrivateKey> decoded = _codec.decodeLocalKeys(
        _codec.encodeLocalKeys(Arrays.asList(privateKey)));

    assertEquals(1, decoded.size());
    assertKeyEquals(privateKey, decoded.get(0));
  }

  @Test
  public void import_accepts_portable_v3_keys() throws Exception
  {
    IronKeysPrivateKey privateKey = _generator.generate("Portable");

    List<IronKeysPrivateKey> decoded = _codec.decodeImport(
        encodeFields(
          "v3",
          privateKey.id,
          privateKey.name,
          privateKey.keyId,
          privateKey.algorithm,
          privateKey.ecPublicKeyBase64,
          privateKey.ecPrivateKeyBase64,
          privateKey.mlKemPublicKeyBase64,
          privateKey.mlKemPrivateKeyBase64,
          privateKey.fingerprint,
          Long.toString(privateKey.createdAtEpochMillis)));

    assertEquals(1, decoded.size());
    assertKeyEquals(privateKey, decoded.get(0));
  }

  @Test
  public void import_rejects_invalid_private_key_material() throws Exception
  {
    IronKeysPrivateKey privateKey = _generator.generate("Broken");
    IronKeysPrivateKey broken = new IronKeysPrivateKey(
        privateKey.id,
        privateKey.name,
        privateKey.keyId,
        privateKey.algorithm,
        privateKey.ecPublicKeyBase64,
        privateKey.ecPrivateKeyBase64,
        privateKey.mlKemPublicKeyBase64,
        privateKey.ecPrivateKeyBase64,
        privateKey.fingerprint,
        privateKey.createdAtEpochMillis);

    assertTrue(_codec.decodeImport(
        _codec.encodeLocalKeys(Arrays.asList(broken))).isEmpty());
  }

  @Test
  public void import_rejects_malformed_backup() throws Exception
  {
    assertTrue(_codec.decodeImport("not-a-valid-ironkeys-backup").isEmpty());
  }

  private static void assertKeyEquals(IronKeysPrivateKey expected,
      IronKeysPrivateKey actual)
  {
    assertEquals(expected.id, actual.id);
    assertEquals(expected.name, actual.name);
    assertEquals(expected.keyId, actual.keyId);
    assertEquals(expected.algorithm, actual.algorithm);
    assertEquals(expected.ecPublicKeyBase64, actual.ecPublicKeyBase64);
    assertEquals(expected.ecPrivateKeyBase64, actual.ecPrivateKeyBase64);
    assertEquals(expected.mlKemPublicKeyBase64, actual.mlKemPublicKeyBase64);
    assertEquals(expected.mlKemPrivateKeyBase64, actual.mlKemPrivateKeyBase64);
    assertEquals(expected.fingerprint, actual.fingerprint);
    assertEquals(expected.createdAtEpochMillis, actual.createdAtEpochMillis);
  }

  private static String encodeFields(String... fields)
  {
    StringBuilder encoded = new StringBuilder();
    for (int i = 0; i < fields.length; i++)
    {
      if (i > 0)
        encoded.append('|');
      encoded.append(java.util.Base64.getUrlEncoder().withoutPadding()
          .encodeToString(fields[i].getBytes(StandardCharsets.UTF_8)));
    }
    return encoded.toString();
  }
}
