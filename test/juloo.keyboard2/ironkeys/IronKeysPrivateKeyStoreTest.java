package juloo.keyboard2.ironkeys;

import java.util.Arrays;
import org.junit.Test;
import static org.junit.Assert.*;

public class IronKeysPrivateKeyStoreTest
{
  @Test
  public void merge_imported_keys_prepends_new_keys_and_skips_duplicates()
  {
    IronKeysPrivateKey current = key("current");
    IronKeysPrivateKey imported = key("imported");
    IronKeysPrivateKey duplicate = key("current");

    IronKeysPrivateKeyStore.MergeResult result =
        IronKeysPrivateKeyStore.mergeImportedKeys(
            Arrays.asList(current), Arrays.asList(imported, duplicate));

    assertEquals(1, result.importedCount);
    assertEquals(1, result.duplicateCount);
    assertEquals(2, result.mergedKeys.size());
    assertEquals(imported.keyId, result.mergedKeys.get(0).keyId);
    assertEquals(current.keyId, result.mergedKeys.get(1).keyId);
  }

  @Test
  public void merge_imported_keys_deduplicates_within_import_file()
  {
    IronKeysPrivateKey first = key("first");
    IronKeysPrivateKey second = key("second");
    IronKeysPrivateKey duplicate = key("first");

    IronKeysPrivateKeyStore.MergeResult result =
        IronKeysPrivateKeyStore.mergeImportedKeys(
            Arrays.<IronKeysPrivateKey>asList(),
            Arrays.asList(first, second, duplicate));

    assertEquals(2, result.importedCount);
    assertEquals(1, result.duplicateCount);
    assertEquals(first.keyId, result.mergedKeys.get(0).keyId);
    assertEquals(second.keyId, result.mergedKeys.get(1).keyId);
  }

  private static IronKeysPrivateKey key(String id)
  {
    return new IronKeysPrivateKey(
        id,
        "Name " + id,
        id,
        "HYBRID_P256_MLKEM768",
        "ec-public-" + id,
        "ec-private-" + id,
        "mlkem-public-" + id,
        "mlkem-private-" + id,
        "fingerprint-" + id,
        1);
  }
}
