package juloo.keyboard2.ironkeys;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.UserManager;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public final class IronKeysPrivateKeyStore
{
  private static final String PREFERENCES_NAME = "ironkeys_private_keys";
  private static final String KEY_ENCRYPTED_PRIVATE_KEYS = "encrypted_private_keys";
  private static final Object MUTATION_LOCK = new Object();

  private final SharedPreferences _preferences;
  private final IronKeysPrivateKeyCodec _codec;
  private final IronKeysPrivateKeyGenerator _generator;
  private final IronKeysKeyDirectoryCipher _cipher;

  public IronKeysPrivateKeyStore(Context context)
  {
    _preferences = storageContext(context).getSharedPreferences(
        PREFERENCES_NAME, Context.MODE_PRIVATE);
    _codec = new IronKeysPrivateKeyCodec();
    _generator = new IronKeysPrivateKeyGenerator();
    _cipher = new IronKeysKeyDirectoryCipher();
  }

  public static boolean isAvailable(Context context)
  {
    if (!IronKeysKeyDirectoryCipher.isSupported())
      return false;
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
    {
      UserManager userManager =
          (UserManager)context.getSystemService(Context.USER_SERVICE);
      return userManager == null || userManager.isUserUnlocked();
    }
    return true;
  }

  public static boolean isKeystoreSupported()
  {
    return IronKeysKeyDirectoryCipher.isSupported();
  }

  public List<IronKeysPrivateKey> load() throws GeneralSecurityException
  {
    String encryptedSnapshot = _preferences.getString(
        KEY_ENCRYPTED_PRIVATE_KEYS, "");
    if (encryptedSnapshot == null || encryptedSnapshot.isEmpty())
      return new ArrayList<IronKeysPrivateKey>();
    byte[] snapshotBytes = _cipher.decrypt(encryptedSnapshot);
    return _codec.decodeLocalKeys(new String(snapshotBytes,
        StandardCharsets.UTF_8));
  }

  public IronKeysPrivateKey create(String name) throws GeneralSecurityException
  {
    IronKeysPrivateKey generatedKey = _generator.generate(name);
    synchronized (MUTATION_LOCK)
    {
      List<IronKeysPrivateKey> keys = loadForMutation();
      keys.add(0, generatedKey);
      save(keys);
    }
    return generatedKey;
  }

  public ImportResult importKeys(String rawValue)
      throws GeneralSecurityException
  {
    List<IronKeysPrivateKey> importedKeys = _codec.decodeImport(rawValue);
    if (importedKeys.isEmpty())
      throw new GeneralSecurityException("Invalid IronKeys private key file.");

    synchronized (MUTATION_LOCK)
    {
      List<IronKeysPrivateKey> currentKeys = loadForMutation();
      MergeResult mergeResult = mergeImportedKeys(currentKeys, importedKeys);
      if (mergeResult.mergedKeys.size() != currentKeys.size())
        save(mergeResult.mergedKeys);
      return new ImportResult(mergeResult.importedCount,
          mergeResult.duplicateCount);
    }
  }

  public void delete(String id) throws GeneralSecurityException
  {
    synchronized (MUTATION_LOCK)
    {
      List<IronKeysPrivateKey> currentKeys = load();
      List<IronKeysPrivateKey> updatedKeys = new ArrayList<IronKeysPrivateKey>();
      for (IronKeysPrivateKey currentKey : currentKeys)
        if (!currentKey.id.equals(id))
          updatedKeys.add(currentKey);
      save(updatedKeys);
    }
  }

  public String exportKeyBackup(IronKeysPrivateKey privateKey)
  {
    List<IronKeysPrivateKey> keys = new ArrayList<IronKeysPrivateKey>();
    keys.add(privateKey);
    return _codec.encodeBackup(keys, privateKey.id);
  }

  private void save(List<IronKeysPrivateKey> keys)
      throws GeneralSecurityException
  {
    byte[] snapshotBytes = _codec.encodeLocalKeys(keys)
        .getBytes(StandardCharsets.UTF_8);
    boolean saved = _preferences.edit()
        .putString(KEY_ENCRYPTED_PRIVATE_KEYS, _cipher.encrypt(snapshotBytes))
        .commit();
    if (!saved)
      throw new GeneralSecurityException(
          "Unable to persist IronKeys private keys.");
  }

  private List<IronKeysPrivateKey> loadForMutation()
      throws GeneralSecurityException
  {
    try
    {
      return load();
    }
    catch (IronKeysMissingWrappingKeyException e)
    {
      // Replaces snapshots restored without their Android Keystore key.
      return new ArrayList<IronKeysPrivateKey>();
    }
  }

  static MergeResult mergeImportedKeys(List<IronKeysPrivateKey> currentKeys,
      List<IronKeysPrivateKey> importedKeys)
  {
    Set<String> existingKeyIds = new LinkedHashSet<String>();
    for (IronKeysPrivateKey currentKey : currentKeys)
      existingKeyIds.add(currentKey.keyId);

    List<IronKeysPrivateKey> mergedKeys = new ArrayList<IronKeysPrivateKey>();
    int duplicateCount = 0;
    for (IronKeysPrivateKey importedKey : importedKeys)
    {
      if (existingKeyIds.contains(importedKey.keyId))
      {
        duplicateCount++;
        continue;
      }
      existingKeyIds.add(importedKey.keyId);
      mergedKeys.add(importedKey);
    }
    mergedKeys.addAll(currentKeys);
    return new MergeResult(mergedKeys,
        importedKeys.size() - duplicateCount, duplicateCount);
  }

  private static Context storageContext(Context context)
  {
    return context.getApplicationContext();
  }

  public static final class ImportResult
  {
    public final int importedCount;
    public final int duplicateCount;

    ImportResult(int importedCount, int duplicateCount)
    {
      this.importedCount = importedCount;
      this.duplicateCount = duplicateCount;
    }
  }

  static final class MergeResult
  {
    final List<IronKeysPrivateKey> mergedKeys;
    final int importedCount;
    final int duplicateCount;

    MergeResult(List<IronKeysPrivateKey> mergedKeys, int importedCount,
        int duplicateCount)
    {
      this.mergedKeys = mergedKeys;
      this.importedCount = importedCount;
      this.duplicateCount = duplicateCount;
    }
  }
}
