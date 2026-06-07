package juloo.keyboard2.ironkeys;

import android.util.Base64;
import java.nio.charset.StandardCharsets;

final class IronKeysBase64
{
  private IronKeysBase64() {}

  static String encode(byte[] value)
  {
    return Base64.encodeToString(value, Base64.NO_WRAP);
  }

  static byte[] decode(String value)
  {
    return Base64.decode(value, Base64.DEFAULT);
  }

  static String encodeUrlString(String value)
  {
    return encodeUrl(value.getBytes(StandardCharsets.UTF_8));
  }

  static String encodeUrl(byte[] value)
  {
    return Base64.encodeToString(value,
        Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
  }

  static String decodeUrlString(String value)
  {
    return new String(decodeUrl(value), StandardCharsets.UTF_8);
  }

  static byte[] decodeUrl(String value)
  {
    return Base64.decode(value,
        Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
  }
}
