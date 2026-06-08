package juloo.keyboard2.ironkeys;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.UserManager;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class IronKeysPublicKeyStore
{
  public static final String BACKUP_FILE_NAME = "ironkeys-public-keys.ikpub";

  private static final String PREFERENCES_NAME = "ironkeys_public_keys";
  private static final String KEY_ENCRYPTED_PUBLIC_KEYS = "encrypted_public_keys";
  private static final Object MUTATION_LOCK = new Object();

  private final SharedPreferences _preferences;
  private final IronKeysPublicKeyShareCodec _shareCodec;
  private final IronKeysPublicKeyDirectoryCodec _directoryCodec;
  private final IronKeysKeyDirectoryCipher _cipher;

  public IronKeysPublicKeyStore(Context context)
  {
    _preferences = storageContext(context).getSharedPreferences(
        PREFERENCES_NAME, Context.MODE_PRIVATE);
    _shareCodec = new IronKeysPublicKeyShareCodec();
    _directoryCodec = new IronKeysPublicKeyDirectoryCodec();
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

  public List<IronKeysPublicKey> load() throws GeneralSecurityException
  {
    String encryptedSnapshot = _preferences.getString(
        KEY_ENCRYPTED_PUBLIC_KEYS, "");
    if (encryptedSnapshot == null || encryptedSnapshot.isEmpty())
      return new ArrayList<IronKeysPublicKey>();

    byte[] snapshotBytes = _cipher.decrypt(encryptedSnapshot);
    List<IronKeysPublicKey> publicKeys = _directoryCodec.decodeStoredKeys(
        new String(snapshotBytes, StandardCharsets.UTF_8));
    if (publicKeys == null)
      throw new GeneralSecurityException(
          "Stored IronKeys public keys are invalid.");
    return publicKeys;
  }

  public String buildPublicKeyShare(IronKeysPrivateKey privateKey)
  {
    return _shareCodec.encode(privateKey);
  }

  public SingleImportResult importPublicKeyShare(String rawShareText)
      throws GeneralSecurityException
  {
    IronKeysPublicKeyShareCodec.DecodeResult decodeResult =
        _shareCodec.decode(rawShareText);
    if (decodeResult.status !=
        IronKeysPublicKeyShareCodec.DecodeResult.Status.SUCCESS)
      throw new PublicKeyImportException(decodeResult.status);

    IronKeysPublicKeyShareCodec.ParsedPublicKeyShare parsed =
        decodeResult.publicKey;
    IronKeysPublicKey importedKey = new IronKeysPublicKey(
        parsed.keyId,
        parsed.name,
        parsed.keyId,
        parsed.algorithm,
        parsed.ecPublicKeyBase64,
        parsed.mlKemPublicKeyBase64,
        parsed.fingerprint,
        System.currentTimeMillis());

    synchronized (MUTATION_LOCK)
    {
      List<IronKeysPublicKey> currentKeys = loadForMutation();
      MergeResult mergeResult = mergeImportedPublicKeys(
          currentKeys, single(importedKey));
      save(mergeResult.mergedKeys);
      return new SingleImportResult(mergeResult.mergedKeys.get(
          mergeResult.importedKeyIndex), mergeResult.addedCount == 1);
    }
  }

  public DirectoryImportResult importPublicKeyDirectory(String rawBackup)
      throws GeneralSecurityException
  {
    List<IronKeysPublicKey> importedKeys =
        _directoryCodec.decodeBackup(rawBackup);
    if (importedKeys == null)
      throw new GeneralSecurityException(
          "Invalid IronKeys public key directory backup.");

    synchronized (MUTATION_LOCK)
    {
      List<IronKeysPublicKey> currentKeys = loadForMutation();
      MergeResult mergeResult =
          mergeImportedPublicKeys(currentKeys, importedKeys);
      if (mergeResult.addedCount > 0 || mergeResult.updatedCount > 0)
        save(mergeResult.mergedKeys);
      return new DirectoryImportResult(
          mergeResult.addedCount,
          mergeResult.updatedCount,
          mergeResult.unchangedCount);
    }
  }

  public String exportPublicKeyDirectory() throws GeneralSecurityException
  {
    return _directoryCodec.encodeBackup(load());
  }

  public void delete(String id) throws GeneralSecurityException
  {
    synchronized (MUTATION_LOCK)
    {
      List<IronKeysPublicKey> currentKeys = load();
      List<IronKeysPublicKey> updatedKeys =
          new ArrayList<IronKeysPublicKey>();
      for (IronKeysPublicKey currentKey : currentKeys)
        if (!currentKey.id.equals(id))
          updatedKeys.add(currentKey);
      save(updatedKeys);
    }
  }

  private void save(List<IronKeysPublicKey> publicKeys)
      throws GeneralSecurityException
  {
    byte[] snapshotBytes = _directoryCodec.encodeStoredKeys(publicKeys)
        .getBytes(StandardCharsets.UTF_8);
    boolean saved = _preferences.edit()
        .putString(KEY_ENCRYPTED_PUBLIC_KEYS, _cipher.encrypt(snapshotBytes))
        .commit();
    if (!saved)
      throw new GeneralSecurityException(
          "Unable to persist IronKeys public keys.");
  }

  private List<IronKeysPublicKey> loadForMutation()
      throws GeneralSecurityException
  {
    try
    {
      return load();
    }
    catch (IronKeysMissingWrappingKeyException e)
    {
      return new ArrayList<IronKeysPublicKey>();
    }
  }

  static MergeResult mergeImportedPublicKeys(List<IronKeysPublicKey> currentKeys,
      List<IronKeysPublicKey> importedKeys)
  {
    Map<String, IronKeysPublicKey> importedByKeyId =
        new LinkedHashMap<String, IronKeysPublicKey>();
    for (IronKeysPublicKey importedKey : importedKeys)
      if (!importedByKeyId.containsKey(importedKey.keyId))
        importedByKeyId.put(importedKey.keyId, importedKey);

    Map<String, IronKeysPublicKey> currentByKeyId =
        new LinkedHashMap<String, IronKeysPublicKey>();
    for (IronKeysPublicKey currentKey : currentKeys)
      currentByKeyId.put(currentKey.keyId, currentKey);

    List<IronKeysPublicKey> mergedKeys = new ArrayList<IronKeysPublicKey>();
    int addedCount = 0;
    int updatedCount = 0;
    int unchangedCount = 0;
    int importedKeyIndex = -1;

    for (IronKeysPublicKey importedKey : importedByKeyId.values())
    {
      if (currentByKeyId.containsKey(importedKey.keyId))
        continue;
      if (importedKeyIndex < 0)
        importedKeyIndex = mergedKeys.size();
      mergedKeys.add(importedKey);
      addedCount++;
    }

    for (IronKeysPublicKey currentKey : currentKeys)
    {
      IronKeysPublicKey importedKey = importedByKeyId.get(currentKey.keyId);
      if (importedKey == null)
      {
        mergedKeys.add(currentKey);
        continue;
      }

      IronKeysPublicKey updatedKey =
          importedKey.withAddedAt(currentKey.addedAtEpochMillis);
      if (samePublicKey(currentKey, updatedKey))
      {
        unchangedCount++;
        if (importedKeyIndex < 0)
          importedKeyIndex = mergedKeys.size();
        mergedKeys.add(currentKey);
      }
      else
      {
        updatedCount++;
        if (importedKeyIndex < 0)
          importedKeyIndex = mergedKeys.size();
        mergedKeys.add(updatedKey);
      }
    }

    if (importedKeyIndex < 0 && !mergedKeys.isEmpty())
      importedKeyIndex = 0;
    return new MergeResult(mergedKeys, addedCount, updatedCount,
        unchangedCount, importedKeyIndex);
  }

  private static boolean samePublicKey(IronKeysPublicKey first,
      IronKeysPublicKey second)
  {
    return first.id.equals(second.id) &&
        first.name.equals(second.name) &&
        first.keyId.equals(second.keyId) &&
        first.algorithm.equals(second.algorithm) &&
        first.ecPublicKeyBase64.equals(second.ecPublicKeyBase64) &&
        first.mlKemPublicKeyBase64.equals(second.mlKemPublicKeyBase64) &&
        first.fingerprint.equals(second.fingerprint) &&
        first.addedAtEpochMillis == second.addedAtEpochMillis;
  }

  private static List<IronKeysPublicKey> single(IronKeysPublicKey publicKey)
  {
    List<IronKeysPublicKey> publicKeys = new ArrayList<IronKeysPublicKey>();
    publicKeys.add(publicKey);
    return publicKeys;
  }

  private static Context storageContext(Context context)
  {
    return context.getApplicationContext();
  }

  public static final class SingleImportResult
  {
    public final IronKeysPublicKey publicKey;
    public final boolean wasAdded;

    SingleImportResult(IronKeysPublicKey publicKey, boolean wasAdded)
    {
      this.publicKey = publicKey;
      this.wasAdded = wasAdded;
    }
  }

  public static final class DirectoryImportResult
  {
    public final int addedCount;
    public final int updatedCount;
    public final int unchangedCount;

    DirectoryImportResult(int addedCount, int updatedCount,
        int unchangedCount)
    {
      this.addedCount = addedCount;
      this.updatedCount = updatedCount;
      this.unchangedCount = unchangedCount;
    }
  }

  public static final class PublicKeyImportException
      extends GeneralSecurityException
  {
    public final IronKeysPublicKeyShareCodec.DecodeResult.Status status;

    PublicKeyImportException(
        IronKeysPublicKeyShareCodec.DecodeResult.Status status)
    {
      super(status.toString());
      this.status = status;
    }
  }

  static final class MergeResult
  {
    final List<IronKeysPublicKey> mergedKeys;
    final int addedCount;
    final int updatedCount;
    final int unchangedCount;
    final int importedKeyIndex;

    MergeResult(List<IronKeysPublicKey> mergedKeys, int addedCount,
        int updatedCount, int unchangedCount, int importedKeyIndex)
    {
      this.mergedKeys = mergedKeys;
      this.addedCount = addedCount;
      this.updatedCount = updatedCount;
      this.unchangedCount = unchangedCount;
      this.importedKeyIndex = importedKeyIndex;
    }
  }
}
