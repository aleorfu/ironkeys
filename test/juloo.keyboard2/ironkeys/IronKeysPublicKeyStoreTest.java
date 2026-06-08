package juloo.keyboard2.ironkeys;

import java.util.Arrays;
import org.junit.Test;
import static org.junit.Assert.*;

public class IronKeysPublicKeyStoreTest
{
  @Test
  public void merge_public_keys_prepends_new_keys_and_updates_existing()
  {
    IronKeysPublicKey current = key("current", "Current", 10);
    IronKeysPublicKey imported = key("imported", "Imported", 20);
    IronKeysPublicKey updated = key("current", "Updated", 30);

    IronKeysPublicKeyStore.MergeResult result =
        IronKeysPublicKeyStore.mergeImportedPublicKeys(
            Arrays.asList(current), Arrays.asList(imported, updated));

    assertEquals(1, result.addedCount);
    assertEquals(1, result.updatedCount);
    assertEquals(0, result.unchangedCount);
    assertEquals(2, result.mergedKeys.size());
    assertEquals(imported.keyId, result.mergedKeys.get(0).keyId);
    assertEquals(updated.name, result.mergedKeys.get(1).name);
    assertEquals(current.addedAtEpochMillis,
        result.mergedKeys.get(1).addedAtEpochMillis);
  }

  @Test
  public void merge_public_keys_counts_unchanged_duplicates()
  {
    IronKeysPublicKey current = key("current", "Current", 10);

    IronKeysPublicKeyStore.MergeResult result =
        IronKeysPublicKeyStore.mergeImportedPublicKeys(
            Arrays.asList(current), Arrays.asList(current));

    assertEquals(0, result.addedCount);
    assertEquals(0, result.updatedCount);
    assertEquals(1, result.unchangedCount);
    assertEquals(1, result.mergedKeys.size());
    assertEquals(current.keyId, result.mergedKeys.get(0).keyId);
  }

  @Test
  public void merge_public_keys_deduplicates_import_file()
  {
    IronKeysPublicKey first = key("first", "First", 10);
    IronKeysPublicKey second = key("second", "Second", 20);
    IronKeysPublicKey duplicate = key("first", "Duplicate", 30);

    IronKeysPublicKeyStore.MergeResult result =
        IronKeysPublicKeyStore.mergeImportedPublicKeys(
            Arrays.<IronKeysPublicKey>asList(),
            Arrays.asList(first, second, duplicate));

    assertEquals(2, result.addedCount);
    assertEquals(0, result.updatedCount);
    assertEquals(0, result.unchangedCount);
    assertEquals(first.name, result.mergedKeys.get(0).name);
    assertEquals(second.name, result.mergedKeys.get(1).name);
  }

  private static IronKeysPublicKey key(String id, String name,
      long addedAtEpochMillis)
  {
    return new IronKeysPublicKey(
        id,
        name,
        id,
        "HYBRID_P256_MLKEM768",
        "ec-public-" + id,
        "mlkem-public-" + id,
        "fingerprint-" + id,
        addedAtEpochMillis);
  }
}
