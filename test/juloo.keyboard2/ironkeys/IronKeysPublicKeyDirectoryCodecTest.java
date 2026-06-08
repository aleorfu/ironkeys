package juloo.keyboard2.ironkeys;

import java.util.Arrays;
import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;

public class IronKeysPublicKeyDirectoryCodecTest
{
  private final IronKeysPrivateKeyGenerator _generator =
      new IronKeysPrivateKeyGenerator();
  private final IronKeysPublicKeyDirectoryCodec _codec =
      new IronKeysPublicKeyDirectoryCodec();

  @Test
  public void directory_backup_round_trip() throws Exception
  {
    IronKeysPublicKey first = publicKey(_generator.generate("First"), 10);
    IronKeysPublicKey second = publicKey(_generator.generate("Second"), 20);

    List<IronKeysPublicKey> decoded = _codec.decodeBackup(
        _codec.encodeBackup(Arrays.asList(first, second)));

    assertEquals(2, decoded.size());
    assertKeyEquals(first, decoded.get(0));
    assertKeyEquals(second, decoded.get(1));
  }

  @Test
  public void directory_backup_accepts_empty_directory()
  {
    List<IronKeysPublicKey> decoded = _codec.decodeBackup(
        _codec.encodeBackup(Arrays.<IronKeysPublicKey>asList()));

    assertTrue(decoded.isEmpty());
  }

  @Test
  public void directory_backup_rejects_malformed_text()
  {
    assertNull(_codec.decodeBackup("not an ironkeys public key backup"));
  }

  @Test
  public void directory_backup_rejects_tampered_keys() throws Exception
  {
    IronKeysPublicKey publicKey = publicKey(_generator.generate("Broken"), 10);
    IronKeysPublicKey tampered = new IronKeysPublicKey(
        publicKey.id,
        publicKey.name,
        publicKey.keyId,
        publicKey.algorithm,
        publicKey.ecPublicKeyBase64,
        publicKey.mlKemPublicKeyBase64,
        "0000 1111",
        publicKey.addedAtEpochMillis);

    assertNull(_codec.decodeBackup(_codec.encodeBackup(Arrays.asList(tampered))));
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

  private static void assertKeyEquals(IronKeysPublicKey expected,
      IronKeysPublicKey actual)
  {
    assertEquals(expected.id, actual.id);
    assertEquals(expected.name, actual.name);
    assertEquals(expected.keyId, actual.keyId);
    assertEquals(expected.algorithm, actual.algorithm);
    assertEquals(expected.ecPublicKeyBase64, actual.ecPublicKeyBase64);
    assertEquals(expected.mlKemPublicKeyBase64, actual.mlKemPublicKeyBase64);
    assertEquals(expected.fingerprint, actual.fingerprint);
    assertEquals(expected.addedAtEpochMillis, actual.addedAtEpochMillis);
  }
}
