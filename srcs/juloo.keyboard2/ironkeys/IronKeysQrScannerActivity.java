package juloo.keyboard2.ironkeys;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RectF;
import android.hardware.Camera;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.Surface;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.View;
import android.view.WindowInsets;
import android.widget.FrameLayout;
import android.widget.TextView;
import android.widget.Toast;
import java.util.List;
import juloo.keyboard2.R;

public final class IronKeysQrScannerActivity extends Activity
  implements SurfaceHolder.Callback, Camera.PreviewCallback
{
  public static final String EXTRA_QR_TEXT =
      "juloo.keyboard2.ironkeys.QR_TEXT";

  private static final int REQUEST_CAMERA_PERMISSION = 2401;

  private final Handler _handler = new Handler(Looper.getMainLooper());
  private PreviewSurfaceView _surfaceView;
  private Camera _camera;
  private TextView _instructionLabel;
  private FrameLayout.LayoutParams _instructionParams;
  private boolean _surfaceReady;
  private volatile boolean _decoding;
  private boolean _finishedWithResult;
  private int _displayOrientation;

  @Override
  protected void onCreate(Bundle savedInstanceState)
  {
    super.onCreate(savedInstanceState);
    buildContentView();
    if (hasCameraPermission())
      startCameraIfReady();
    else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
      requestPermissions(new String[] { Manifest.permission.CAMERA },
          REQUEST_CAMERA_PERMISSION);
    else
      finishWithoutCameraPermission();
  }

  @Override
  protected void onResume()
  {
    super.onResume();
    startCameraIfReady();
  }

  @Override
  protected void onPause()
  {
    releaseCamera();
    super.onPause();
  }

  @Override
  public void onRequestPermissionsResult(int requestCode,
      String[] permissions, int[] grantResults)
  {
    super.onRequestPermissionsResult(requestCode, permissions, grantResults);
    if (requestCode != REQUEST_CAMERA_PERMISSION)
      return;
    if (grantResults.length > 0 &&
        grantResults[0] == PackageManager.PERMISSION_GRANTED)
      startCameraIfReady();
    else
      finishWithoutCameraPermission();
  }

  @Override
  public void surfaceCreated(SurfaceHolder holder)
  {
    _surfaceReady = true;
    startCameraIfReady();
  }

  @Override
  public void surfaceChanged(SurfaceHolder holder, int format, int width,
      int height)
  {
    if (_camera == null)
      return;
    try
    {
      _camera.stopPreview();
    }
    catch (Exception e) {}
    startPreview();
  }

  @Override
  public void surfaceDestroyed(SurfaceHolder holder)
  {
    _surfaceReady = false;
    releaseCamera();
  }

  @Override
  public void onPreviewFrame(byte[] data, Camera camera)
  {
    if (_decoding || _finishedWithResult || data == null || camera == null)
      return;
    Camera.Size size = camera.getParameters().getPreviewSize();
    if (size == null)
      return;

    _decoding = true;
    final byte[] frame = data.clone();
    final int width = size.width;
    final int height = size.height;
    new Thread(() -> {
      final String text = IronKeysQrCode.decodePreviewFrame(frame, width, height);
      _handler.post(() -> {
        if (text != null)
          finishWithResult(text);
        else
          _decoding = false;
      });
    }, "IronKeys-qr-decode").start();
  }

  private void buildContentView()
  {
    FrameLayout root = new FrameLayout(this);
    root.setBackgroundColor(Color.BLACK);
    _surfaceView = new PreviewSurfaceView(this);
    _surfaceView.getHolder().addCallback(this);
    FrameLayout.LayoutParams previewParams = new FrameLayout.LayoutParams(
        FrameLayout.LayoutParams.MATCH_PARENT,
        FrameLayout.LayoutParams.MATCH_PARENT,
        Gravity.CENTER);
    root.addView(_surfaceView, previewParams);

    root.addView(new FinderOverlayView(this), new FrameLayout.LayoutParams(
        FrameLayout.LayoutParams.MATCH_PARENT,
        FrameLayout.LayoutParams.MATCH_PARENT));

    _instructionLabel = new TextView(this);
    _instructionLabel.setText(R.string.ironkeys_scan_public_key_instruction);
    _instructionLabel.setGravity(Gravity.CENTER);
    _instructionLabel.setTextColor(android.graphics.Color.WHITE);
    _instructionLabel.setBackgroundColor(0x99000000);
    int padding = dp(16);
    _instructionLabel.setPadding(padding, padding, padding, padding);
    FrameLayout.LayoutParams labelParams = new FrameLayout.LayoutParams(
        FrameLayout.LayoutParams.MATCH_PARENT,
        FrameLayout.LayoutParams.WRAP_CONTENT,
        Gravity.BOTTOM);
    _instructionParams = labelParams;
    applyInstructionBottomMargin(fallbackNavigationMargin());
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
      _instructionLabel.setOnApplyWindowInsetsListener((view, insets) -> {
        applyInstructionBottomMargin(navigationBottomInset(insets));
        return insets;
      });
    root.addView(_instructionLabel, labelParams);
    setContentView(root);
  }

  private void startCameraIfReady()
  {
    if (!_surfaceReady || !hasCameraPermission() || _camera != null)
      return;
    try
    {
      _camera = Camera.open();
      _displayOrientation = cameraDisplayOrientation();
      _camera.setDisplayOrientation(_displayOrientation);
      configureCamera(_camera);
      _camera.setPreviewDisplay(_surfaceView.getHolder());
      _camera.setPreviewCallback(this);
      startPreview();
    }
    catch (Exception e)
    {
      releaseCamera();
      Toast.makeText(this, R.string.ironkeys_scan_public_key_camera_failed,
          Toast.LENGTH_LONG).show();
      setResult(RESULT_CANCELED);
      finish();
    }
  }

  private void startPreview()
  {
    if (_camera == null)
      return;
    try
    {
      _camera.setPreviewDisplay(_surfaceView.getHolder());
      _camera.setPreviewCallback(this);
      _camera.startPreview();
    }
    catch (Exception e)
    {
      releaseCamera();
    }
  }

  private void configureCamera(Camera camera)
  {
    try
    {
      Camera.Parameters parameters = camera.getParameters();
      Camera.Size previewSize = choosePreviewSize(
          parameters.getSupportedPreviewSizes());
      if (previewSize != null)
      {
        parameters.setPreviewSize(previewSize.width, previewSize.height);
        if (_displayOrientation == 90 || _displayOrientation == 270)
          _surfaceView.setPreviewSize(previewSize.height, previewSize.width);
        else
          _surfaceView.setPreviewSize(previewSize.width, previewSize.height);
      }
      List<String> focusModes = parameters.getSupportedFocusModes();
      if (focusModes != null &&
          focusModes.contains(Camera.Parameters.FOCUS_MODE_CONTINUOUS_PICTURE))
        parameters.setFocusMode(Camera.Parameters.FOCUS_MODE_CONTINUOUS_PICTURE);
      else if (focusModes != null &&
          focusModes.contains(Camera.Parameters.FOCUS_MODE_CONTINUOUS_VIDEO))
        parameters.setFocusMode(Camera.Parameters.FOCUS_MODE_CONTINUOUS_VIDEO);
      else if (focusModes != null &&
          focusModes.contains(Camera.Parameters.FOCUS_MODE_AUTO))
        parameters.setFocusMode(Camera.Parameters.FOCUS_MODE_AUTO);
      camera.setParameters(parameters);
    }
    catch (Exception e) {}
  }

  private Camera.Size choosePreviewSize(List<Camera.Size> supportedSizes)
  {
    if (supportedSizes == null || supportedSizes.isEmpty())
      return null;
    Camera.Size bestSize = null;
    for (Camera.Size size : supportedSizes)
    {
      if (bestSize == null || area(size) > area(bestSize))
        bestSize = size;
    }
    return bestSize;
  }

  private int area(Camera.Size size)
  {
    return size.width * size.height;
  }

  private int cameraDisplayOrientation()
  {
    Camera.CameraInfo info = new Camera.CameraInfo();
    Camera.getCameraInfo(0, info);
    int rotation = getWindowManager().getDefaultDisplay().getRotation();
    int degrees;
    switch (rotation)
    {
      case Surface.ROTATION_90: degrees = 90; break;
      case Surface.ROTATION_180: degrees = 180; break;
      case Surface.ROTATION_270: degrees = 270; break;
      default: degrees = 0; break;
    }
    if (info.facing == Camera.CameraInfo.CAMERA_FACING_FRONT)
      return (360 - ((info.orientation + degrees) % 360)) % 360;
    return (info.orientation - degrees + 360) % 360;
  }

  private void releaseCamera()
  {
    if (_camera == null)
      return;
    try
    {
      _camera.setPreviewCallback(null);
      _camera.stopPreview();
    }
    catch (Exception e) {}
    _camera.release();
    _camera = null;
    _decoding = false;
  }

  private boolean hasCameraPermission()
  {
    return Build.VERSION.SDK_INT < Build.VERSION_CODES.M ||
        checkSelfPermission(Manifest.permission.CAMERA) ==
            PackageManager.PERMISSION_GRANTED;
  }

  private void finishWithoutCameraPermission()
  {
    Toast.makeText(this, R.string.ironkeys_scan_public_key_permission_denied,
        Toast.LENGTH_LONG).show();
    setResult(RESULT_CANCELED);
    finish();
  }

  private void finishWithResult(String text)
  {
    if (_finishedWithResult)
      return;
    _finishedWithResult = true;
    Intent data = new Intent();
    data.putExtra(EXTRA_QR_TEXT, text);
    setResult(RESULT_OK, data);
    finish();
  }

  private int dp(int value)
  {
    return Math.round(value * getResources().getDisplayMetrics().density);
  }

  private int fallbackNavigationMargin()
  {
    return dp(24);
  }

  private int navigationBottomInset(WindowInsets insets)
  {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
      return Math.max(insets.getInsets(
          WindowInsets.Type.navigationBars()).bottom, fallbackNavigationMargin());
    return Math.max(insets.getStableInsetBottom(), fallbackNavigationMargin());
  }

  private void applyInstructionBottomMargin(int bottomMargin)
  {
    if (_instructionParams != null)
    {
      _instructionParams.setMargins(0, 0, 0, bottomMargin);
      if (_instructionLabel != null)
        _instructionLabel.setLayoutParams(_instructionParams);
    }
  }

  private static final class PreviewSurfaceView extends SurfaceView
  {
    private int _previewWidth;
    private int _previewHeight;

    PreviewSurfaceView(Context context)
    {
      super(context);
    }

    void setPreviewSize(int width, int height)
    {
      _previewWidth = width;
      _previewHeight = height;
      requestLayout();
    }

    @Override
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec)
    {
      int availableWidth = MeasureSpec.getSize(widthMeasureSpec);
      int availableHeight = MeasureSpec.getSize(heightMeasureSpec);
      if (_previewWidth <= 0 || _previewHeight <= 0 ||
          availableWidth <= 0 || availableHeight <= 0)
      {
        setMeasuredDimension(availableWidth, availableHeight);
        return;
      }

      float previewRatio = (float)_previewWidth / (float)_previewHeight;
      float availableRatio = (float)availableWidth / (float)availableHeight;
      if (availableRatio > previewRatio)
      {
        int measuredHeight = Math.round(availableWidth / previewRatio);
        setMeasuredDimension(availableWidth, measuredHeight);
      }
      else
      {
        int measuredWidth = Math.round(availableHeight * previewRatio);
        setMeasuredDimension(measuredWidth, availableHeight);
      }
    }
  }

  private final class FinderOverlayView extends View
  {
    private final Paint _shadePaint = new Paint();
    private final Paint _framePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint _cornerPaint = new Paint(Paint.ANTI_ALIAS_FLAG);

    FinderOverlayView(Context context)
    {
      super(context);
      _shadePaint.setColor(0x66000000);
      _shadePaint.setStyle(Paint.Style.FILL);
      _framePaint.setColor(0xccffffff);
      _framePaint.setStyle(Paint.Style.STROKE);
      _framePaint.setStrokeWidth(dp(2));
      _cornerPaint.setColor(Color.WHITE);
      _cornerPaint.setStyle(Paint.Style.STROKE);
      _cornerPaint.setStrokeWidth(dp(4));
      _cornerPaint.setStrokeCap(Paint.Cap.SQUARE);
    }

    @Override
    protected void onDraw(Canvas canvas)
    {
      super.onDraw(canvas);
      int width = getWidth();
      int height = getHeight();
      if (width <= 0 || height <= 0)
        return;

      float frameSize = Math.min(width * 0.72f, height * 0.46f);
      float left = (width - frameSize) / 2f;
      float top = (height - frameSize) / 2f;
      RectF frame = new RectF(left, top, left + frameSize, top + frameSize);

      canvas.drawRect(0, 0, width, frame.top, _shadePaint);
      canvas.drawRect(0, frame.bottom, width, height, _shadePaint);
      canvas.drawRect(0, frame.top, frame.left, frame.bottom, _shadePaint);
      canvas.drawRect(frame.right, frame.top, width, frame.bottom, _shadePaint);
      canvas.drawRoundRect(frame, dp(8), dp(8), _framePaint);

      float cornerLength = frameSize * 0.16f;
      drawCorner(canvas, frame.left, frame.top, cornerLength, 1, 1);
      drawCorner(canvas, frame.right, frame.top, cornerLength, -1, 1);
      drawCorner(canvas, frame.left, frame.bottom, cornerLength, 1, -1);
      drawCorner(canvas, frame.right, frame.bottom, cornerLength, -1, -1);
    }

    private void drawCorner(Canvas canvas, float x, float y, float length,
        int horizontalDirection, int verticalDirection)
    {
      canvas.drawLine(x, y, x + (length * horizontalDirection), y,
          _cornerPaint);
      canvas.drawLine(x, y, x, y + (length * verticalDirection),
          _cornerPaint);
    }
  }
}
