package juloo.keyboard2;

import android.app.AlertDialog;
import android.app.Activity;
import android.content.Intent;
import android.content.res.Configuration;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.preference.Preference;
import android.preference.PreferenceActivity;
import android.preference.PreferenceCategory;
import android.preference.PreferenceGroup;
import android.preference.PreferenceManager;
import android.preference.PreferenceScreen;
import android.widget.EditText;
import android.widget.Toast;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.util.Date;
import java.util.List;
import juloo.keyboard2.ironkeys.IronKeysPrivateKey;
import juloo.keyboard2.ironkeys.IronKeysPrivateKeyStore;

public class SettingsActivity extends PreferenceActivity
{
  private static final int REQUEST_IRONKEYS_EXPORT_PRIVATE_KEY = 1401;
  private static final int REQUEST_IRONKEYS_IMPORT_PRIVATE_KEY = 1402;
  private static final String STATE_PENDING_IRONKEYS_EXPORT_KEY_ID =
      "pending_ironkeys_export_key_id";
  private static final int MAX_IRONKEYS_PRIVATE_KEY_IMPORT_BYTES =
      1024 * 1024;

  private PreferenceScreen _ironKeysPrivateKeysScreen;
  private String _pendingIronKeysExportKeyId;

  @Override
  public void onCreate(Bundle savedInstanceState)
  {
    super.onCreate(savedInstanceState);
    // The preferences can't be read when in direct-boot mode. Avoid crashing
    // and don't allow changing the settings.
    // Run the config migration on this prefs as it might be different from the
    // one used by the keyboard, which have been migrated.
    try
    {
      Config.migrate(getPreferenceManager().getSharedPreferences());
    }
    catch (Exception _e) { fallbackEncrypted(); return; }
    addPreferencesFromResource(R.xml.settings);

    boolean foldableDevice = FoldStateTracker.isFoldableDevice(this);
    findPreference("margin_bottom_portrait_unfolded").setEnabled(foldableDevice);
    findPreference("margin_bottom_landscape_unfolded").setEnabled(foldableDevice);
    findPreference("horizontal_margin_portrait_unfolded").setEnabled(foldableDevice);
    findPreference("horizontal_margin_landscape_unfolded").setEnabled(foldableDevice);
    findPreference("keyboard_height_unfolded").setEnabled(foldableDevice);
    findPreference("keyboard_height_landscape_unfolded").setEnabled(foldableDevice);

    _ironKeysPrivateKeysScreen =
      (PreferenceScreen)findPreference("ironkeys_private_keys_screen");
    if (savedInstanceState != null)
      _pendingIronKeysExportKeyId = savedInstanceState.getString(
          STATE_PENDING_IRONKEYS_EXPORT_KEY_ID);
    refreshIronKeysPrivateKeysCategory();
  }

  void fallbackEncrypted()
  {
    // Can't communicate with the user here.
    finish();
  }

  protected void onStop()
  {
    DirectBootAwarePreferences
      .copy_preferences_to_protected_storage(this,
          getPreferenceManager().getSharedPreferences());
    super.onStop();
  }

  @Override
  protected void onSaveInstanceState(Bundle outState)
  {
    super.onSaveInstanceState(outState);
    if (_pendingIronKeysExportKeyId != null)
      outState.putString(STATE_PENDING_IRONKEYS_EXPORT_KEY_ID,
          _pendingIronKeysExportKeyId);
  }

  @Override
  protected void onActivityResult(int requestCode, int resultCode, Intent data)
  {
    super.onActivityResult(requestCode, resultCode, data);
    if (requestCode == REQUEST_IRONKEYS_EXPORT_PRIVATE_KEY)
    {
      if (resultCode == Activity.RESULT_OK && data != null &&
          data.getData() != null)
        finishIronKeysPrivateKeyExport(data.getData());
      else
        _pendingIronKeysExportKeyId = null;
      return;
    }

    if (resultCode != Activity.RESULT_OK || data == null || data.getData() == null)
      return;

    if (requestCode == REQUEST_IRONKEYS_IMPORT_PRIVATE_KEY)
      finishIronKeysPrivateKeyImport(data.getData());
  }

  private void refreshIronKeysPrivateKeysCategory()
  {
    if (_ironKeysPrivateKeysScreen == null)
      return;
    _ironKeysPrivateKeysScreen.removeAll();

    if (!IronKeysPrivateKeyStore.isKeystoreSupported())
    {
      addDisabledIronKeysPreference(
          _ironKeysPrivateKeysScreen,
          R.string.ironkeys_private_keys_unavailable_title,
          R.string.ironkeys_private_keys_android_version_unavailable);
      return;
    }
    if (!IronKeysPrivateKeyStore.isAvailable(this))
    {
      addDisabledIronKeysPreference(
          _ironKeysPrivateKeysScreen,
          R.string.ironkeys_private_keys_unavailable_title,
          R.string.ironkeys_private_keys_locked_unavailable);
      return;
    }

    PreferenceCategory generationCategory = new PreferenceCategory(this);
    generationCategory.setTitle(R.string.ironkeys_private_keys_generation_category);
    _ironKeysPrivateKeysScreen.addPreference(generationCategory);
    Preference generatePreference = new Preference(this);
    generatePreference.setPersistent(false);
    generatePreference.setTitle(R.string.ironkeys_generate_private_key);
    generatePreference.setSummary(R.string.ironkeys_generate_private_key_summary);
    generatePreference.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
      @Override
      public boolean onPreferenceClick(Preference _preference)
      {
        showIronKeysGeneratePrivateKeyDialog();
        return true;
      }
    });
    generationCategory.addPreference(generatePreference);

    PreferenceCategory importCategory = new PreferenceCategory(this);
    importCategory.setTitle(R.string.ironkeys_private_keys_import_category);
    _ironKeysPrivateKeysScreen.addPreference(importCategory);
    Preference importPreference = new Preference(this);
    importPreference.setPersistent(false);
    importPreference.setTitle(R.string.ironkeys_import_private_key);
    importPreference.setSummary(R.string.ironkeys_import_private_key_summary);
    importPreference.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
      @Override
      public boolean onPreferenceClick(Preference _preference)
      {
        startIronKeysPrivateKeyImport();
        return true;
      }
    });
    importCategory.addPreference(importPreference);

    PreferenceCategory keyListCategory = new PreferenceCategory(this);
    keyListCategory.setTitle(R.string.ironkeys_private_keys_list_category);
    _ironKeysPrivateKeysScreen.addPreference(keyListCategory);

    try
    {
      List<IronKeysPrivateKey> privateKeys = ironKeysPrivateKeyStore().load();
      if (privateKeys.isEmpty())
      {
        addDisabledIronKeysPreference(
            keyListCategory,
            R.string.ironkeys_no_private_keys_title,
            R.string.ironkeys_no_private_keys_summary);
        return;
      }

      for (final IronKeysPrivateKey privateKey : privateKeys)
      {
        Preference keyPreference = new Preference(this);
        keyPreference.setPersistent(false);
        keyPreference.setTitle(privateKey.name);
        keyPreference.setSummary(getString(
            R.string.ironkeys_private_key_summary,
            privateKey.algorithm,
            privateKey.fingerprint,
            formatIronKeysDate(privateKey.createdAtEpochMillis)));
        keyPreference.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
          @Override
          public boolean onPreferenceClick(Preference _preference)
          {
            showIronKeysPrivateKeyActions(privateKey);
            return true;
          }
        });
        keyListCategory.addPreference(keyPreference);
      }
    }
    catch (Exception e)
    {
      addDisabledIronKeysPreference(
          keyListCategory,
          R.string.ironkeys_private_keys_unavailable_title,
          R.string.ironkeys_private_keys_read_error);
    }
  }

  private void addDisabledIronKeysPreference(PreferenceGroup group,
      int titleResId, int summaryResId)
  {
    Preference preference = new Preference(this);
    preference.setPersistent(false);
    preference.setEnabled(false);
    preference.setTitle(titleResId);
    preference.setSummary(summaryResId);
    group.addPreference(preference);
  }

  private void showIronKeysGeneratePrivateKeyDialog()
  {
    final EditText input = new EditText(this);
    input.setSingleLine(true);
    input.setText(defaultIronKeysPrivateKeyName());
    input.selectAll();

    new AlertDialog.Builder(this)
      .setTitle(R.string.ironkeys_generate_private_key)
      .setView(input)
      .setPositiveButton(R.string.ironkeys_generate, (dialog, _which) -> {
        String name = input.getText().toString().trim();
        if (name.isEmpty())
          name = defaultIronKeysPrivateKeyName();
        createIronKeysPrivateKey(name);
      })
      .setNegativeButton(android.R.string.cancel, null)
      .show();
  }

  private void createIronKeysPrivateKey(String name)
  {
    runIronKeysBackgroundTask("IronKeys-create-private-key", () -> {
      final IronKeysPrivateKey privateKey = ironKeysPrivateKeyStore().create(name);
      runIronKeysUiUpdate(() -> {
        Toast.makeText(this,
            getString(R.string.ironkeys_private_key_created, privateKey.name),
            Toast.LENGTH_LONG).show();
        refreshIronKeysPrivateKeysCategory();
      });
    }, () -> {
      Toast.makeText(this, R.string.ironkeys_private_key_create_failed,
          Toast.LENGTH_LONG).show();
    });
  }

  private void showIronKeysPrivateKeyActions(final IronKeysPrivateKey privateKey)
  {
    new AlertDialog.Builder(this)
      .setTitle(privateKey.name)
      .setMessage(getString(
          R.string.ironkeys_private_key_details,
          privateKey.keyId,
          privateKey.algorithm,
          privateKey.fingerprint,
          formatIronKeysDate(privateKey.createdAtEpochMillis)))
      .setPositiveButton(R.string.ironkeys_export_private_key,
          (alertDialog, _which) -> confirmIronKeysPrivateKeyExport(privateKey))
      .setNegativeButton(R.string.ironkeys_delete_private_key,
          (alertDialog, _which) -> confirmIronKeysPrivateKeyDelete(privateKey))
      .show();
  }

  private void confirmIronKeysPrivateKeyExport(final IronKeysPrivateKey privateKey)
  {
    new AlertDialog.Builder(this)
      .setTitle(R.string.ironkeys_export_private_key)
      .setMessage(R.string.ironkeys_export_private_key_warning)
      .setPositiveButton(R.string.ironkeys_export_private_key,
          (dialog, _which) -> startIronKeysPrivateKeyExport(privateKey))
      .setNegativeButton(android.R.string.cancel, null)
      .show();
  }

  private void confirmIronKeysPrivateKeyDelete(final IronKeysPrivateKey privateKey)
  {
    new AlertDialog.Builder(this)
      .setTitle(R.string.ironkeys_delete_private_key)
      .setMessage(getString(R.string.ironkeys_delete_private_key_confirm,
          privateKey.name))
      .setPositiveButton(android.R.string.ok, (dialog, _which) -> {
        deleteIronKeysPrivateKey(privateKey.id);
      })
      .setNegativeButton(android.R.string.cancel, null)
      .show();
  }

  private void deleteIronKeysPrivateKey(final String id)
  {
    runIronKeysBackgroundTask("IronKeys-delete-private-key", () -> {
      ironKeysPrivateKeyStore().delete(id);
      runIronKeysUiUpdate(() -> {
        Toast.makeText(this, R.string.ironkeys_private_key_deleted,
            Toast.LENGTH_LONG).show();
        refreshIronKeysPrivateKeysCategory();
      });
    }, () -> {
      Toast.makeText(this, R.string.ironkeys_private_key_delete_failed,
          Toast.LENGTH_LONG).show();
    });
  }

  private void startIronKeysPrivateKeyExport(IronKeysPrivateKey privateKey)
  {
    _pendingIronKeysExportKeyId = privateKey.id;
    Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
    intent.addCategory(Intent.CATEGORY_OPENABLE);
    intent.setType("application/octet-stream");
    intent.putExtra(Intent.EXTRA_TITLE, privateKey.safeFileName());
    startActivityForResult(intent, REQUEST_IRONKEYS_EXPORT_PRIVATE_KEY);
  }

  private void finishIronKeysPrivateKeyExport(Uri uri)
  {
    final String privateKeyId = _pendingIronKeysExportKeyId;
    _pendingIronKeysExportKeyId = null;
    if (privateKeyId == null)
      return;

    runIronKeysBackgroundTask("IronKeys-export-private-key", () -> {
      IronKeysPrivateKey privateKey = findIronKeysPrivateKey(privateKeyId);
      if (privateKey == null)
        throw new IOException("Pending IronKeys private key was not found.");
      String backup = ironKeysPrivateKeyStore().exportKeyBackup(privateKey);
      writeText(uri, backup);
      runIronKeysUiUpdate(() -> {
        Toast.makeText(this, R.string.ironkeys_private_key_exported,
            Toast.LENGTH_LONG).show();
      });
    }, () -> {
      Toast.makeText(this, R.string.ironkeys_private_key_export_failed,
          Toast.LENGTH_LONG).show();
    });
  }

  private IronKeysPrivateKey findIronKeysPrivateKey(String id)
      throws java.security.GeneralSecurityException
  {
    List<IronKeysPrivateKey> privateKeys = ironKeysPrivateKeyStore().load();
    for (IronKeysPrivateKey privateKey : privateKeys)
      if (privateKey.id.equals(id))
        return privateKey;
    return null;
  }

  private void startIronKeysPrivateKeyImport()
  {
    Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
    intent.addCategory(Intent.CATEGORY_OPENABLE);
    intent.setType("*/*");
    intent.putExtra(Intent.EXTRA_MIME_TYPES,
        new String[] { "text/plain", "application/octet-stream" });
    startActivityForResult(intent, REQUEST_IRONKEYS_IMPORT_PRIVATE_KEY);
  }

  private void finishIronKeysPrivateKeyImport(Uri uri)
  {
    runIronKeysBackgroundTask("IronKeys-import-private-key", () -> {
      final IronKeysPrivateKeyStore.ImportResult result =
          ironKeysPrivateKeyStore().importKeys(readText(uri,
              MAX_IRONKEYS_PRIVATE_KEY_IMPORT_BYTES));
      runIronKeysUiUpdate(() -> {
        Toast.makeText(this,
            getString(R.string.ironkeys_private_key_imported,
                result.importedCount, result.duplicateCount),
            Toast.LENGTH_LONG).show();
        refreshIronKeysPrivateKeysCategory();
      });
    }, new IronKeysBackgroundFailureHandler()
    {
      @Override
      public void onFailure(Exception e)
      {
        int messageResId = e instanceof IronKeysPrivateKeyImportTooLargeException
            ? R.string.ironkeys_private_key_import_too_large
            : R.string.ironkeys_private_key_import_failed;
        Toast.makeText(SettingsActivity.this, messageResId,
            Toast.LENGTH_LONG).show();
      }
    });
  }

  private IronKeysPrivateKeyStore ironKeysPrivateKeyStore()
  {
    return new IronKeysPrivateKeyStore(this);
  }

  private String defaultIronKeysPrivateKeyName()
  {
    try
    {
      return getString(R.string.ironkeys_default_private_key_name,
          ironKeysPrivateKeyStore().load().size() + 1);
    }
    catch (Exception e)
    {
      return getString(R.string.ironkeys_default_private_key_name, 1);
    }
  }

  private String formatIronKeysDate(long epochMillis)
  {
    return DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)
      .format(new Date(epochMillis));
  }

  private void writeText(Uri uri, String value) throws IOException
  {
    OutputStream outputStream = getContentResolver().openOutputStream(uri);
    if (outputStream == null)
      throw new IOException("Unable to open output stream.");
    try
    {
      outputStream.write(value.getBytes(StandardCharsets.UTF_8));
    }
    finally
    {
      outputStream.close();
    }
  }

  private String readText(Uri uri, int maxBytes) throws IOException
  {
    InputStream inputStream = getContentResolver().openInputStream(uri);
    if (inputStream == null)
      throw new IOException("Unable to open input stream.");
    try
    {
      ByteArrayOutputStream buffer = new ByteArrayOutputStream();
      byte[] chunk = new byte[8192];
      int read;
      int totalRead = 0;
      while ((read = inputStream.read(chunk)) != -1)
      {
        totalRead += read;
        if (totalRead > maxBytes)
          throw new IronKeysPrivateKeyImportTooLargeException();
        buffer.write(chunk, 0, read);
      }
      return new String(buffer.toByteArray(), StandardCharsets.UTF_8);
    }
    finally
    {
      inputStream.close();
    }
  }

  private static final class IronKeysPrivateKeyImportTooLargeException
      extends IOException
  {
  }

  private interface IronKeysBackgroundOperation
  {
    void run() throws Exception;
  }

  private interface IronKeysBackgroundFailureHandler
  {
    void onFailure(Exception e);
  }

  private void runIronKeysBackgroundTask(String threadName,
      final IronKeysBackgroundOperation operation,
      final Runnable failureHandler)
  {
    runIronKeysBackgroundTask(threadName, operation,
        new IronKeysBackgroundFailureHandler()
        {
          @Override
          public void onFailure(Exception e)
          {
            failureHandler.run();
          }
        });
  }

  private void runIronKeysBackgroundTask(String threadName,
      final IronKeysBackgroundOperation operation,
      final IronKeysBackgroundFailureHandler failureHandler)
  {
    new Thread(() -> {
      try
      {
        operation.run();
      }
      catch (final Exception e)
      {
        runIronKeysUiUpdate(() -> failureHandler.onFailure(e));
      }
    }, threadName).start();
  }

  private void runIronKeysUiUpdate(final Runnable update)
  {
    runOnUiThread(() -> {
      if (isFinishing() || isDestroyed())
        return;
      update.run();
    });
  }
}
