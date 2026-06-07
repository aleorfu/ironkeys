package juloo.keyboard2.ironkeys;

import android.os.Build;
import java.security.GeneralSecurityException;

final class IronKeysKeyDirectoryCipher
{
  private static final String KEY_DIRECTORY_ALIAS =
      "unexpected_keyboard_ironkeys_private_keys";

  private final IronKeysSecretKeyBox _secretKeyBox;

  IronKeysKeyDirectoryCipher()
  {
    _secretKeyBox = new IronKeysSecretKeyBox();
  }

  String encrypt(byte[] snapshotBytes) throws GeneralSecurityException
  {
    ensureSupported();
    return IronKeysBase64.encode(_secretKeyBox.encrypt(KEY_DIRECTORY_ALIAS,
        snapshotBytes));
  }

  byte[] decrypt(String encodedValue) throws GeneralSecurityException
  {
    ensureSupported();
    return _secretKeyBox.decrypt(KEY_DIRECTORY_ALIAS,
        IronKeysBase64.decode(encodedValue));
  }

  static boolean isSupported()
  {
    return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M;
  }

  private static void ensureSupported() throws GeneralSecurityException
  {
    if (!isSupported())
      throw new GeneralSecurityException("IronKeys private keys require Android 6.0 or newer.");
  }
}
