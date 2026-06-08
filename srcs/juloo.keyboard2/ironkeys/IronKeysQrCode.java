package juloo.keyboard2.ironkeys;

import android.graphics.Bitmap;
import android.graphics.Color;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.EncodeHintType;
import com.google.zxing.InvertedLuminanceSource;
import com.google.zxing.LuminanceSource;
import com.google.zxing.PlanarYUVLuminanceSource;
import com.google.zxing.Result;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import java.util.EnumMap;
import java.util.Map;

public final class IronKeysQrCode
{
  private IronKeysQrCode() {}

  public static Bitmap encodeBitmap(String content, int size)
      throws WriterException
  {
    Map<EncodeHintType, Object> hints =
        new EnumMap<EncodeHintType, Object>(EncodeHintType.class);
    hints.put(EncodeHintType.CHARACTER_SET, "UTF-8");
    hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M);
    BitMatrix matrix = new QRCodeWriter().encode(content,
        BarcodeFormat.QR_CODE, size, size, hints);

    Bitmap bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888);
    for (int y = 0; y < size; y++)
      for (int x = 0; x < size; x++)
        bitmap.setPixel(x, y, matrix.get(x, y) ? Color.BLACK : Color.WHITE);
    return bitmap;
  }

  public static String decodePreviewFrame(byte[] data, int width, int height)
  {
    Frame frame = new Frame(data, width, height);
    String result = decodeFrame(frame);
    if (result != null)
      return result;
    result = decodeFrame(frame.rotate90());
    if (result != null)
      return result;
    result = decodeFrame(frame.rotate180());
    if (result != null)
      return result;
    return decodeFrame(frame.rotate270());
  }

  private static String decodeFrame(Frame frame)
  {
    LuminanceSource source = new PlanarYUVLuminanceSource(
        frame.data,
        frame.width,
        frame.height,
        0,
        0,
        frame.width,
        frame.height,
        false);
    String result = decodeSource(source);
    if (result != null)
      return result;
    return decodeSource(new InvertedLuminanceSource(source));
  }

  private static String decodeSource(LuminanceSource source)
  {
    try
    {
      Result result = new QRCodeReader()
          .decode(new BinaryBitmap(new HybridBinarizer(source)));
      return result == null ? null : result.getText();
    }
    catch (Exception e)
    {
      return null;
    }
  }

  private static final class Frame
  {
    final byte[] data;
    final int width;
    final int height;

    Frame(byte[] data, int width, int height)
    {
      this.data = data;
      this.width = width;
      this.height = height;
    }

    Frame rotate90()
    {
      byte[] rotated = new byte[data.length];
      for (int y = 0; y < height; y++)
        for (int x = 0; x < width; x++)
          rotated[(x * height) + (height - y - 1)] = data[(y * width) + x];
      return new Frame(rotated, height, width);
    }

    Frame rotate180()
    {
      byte[] rotated = new byte[data.length];
      int luminanceLength = width * height;
      for (int i = 0; i < luminanceLength; i++)
        rotated[luminanceLength - i - 1] = data[i];
      return new Frame(rotated, width, height);
    }

    Frame rotate270()
    {
      byte[] rotated = new byte[data.length];
      for (int y = 0; y < height; y++)
        for (int x = 0; x < width; x++)
          rotated[((width - x - 1) * height) + y] = data[(y * width) + x];
      return new Frame(rotated, height, width);
    }
  }
}
