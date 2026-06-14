package juloo.keyboard2;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.graphics.drawable.Drawable;
import android.inputmethodservice.InputMethodService;
import android.os.Build.VERSION;
import android.os.Handler;
import android.os.IBinder;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.util.Log;
import android.util.LogPrinter;
import android.view.*;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.view.inputmethod.InputMethodManager;
import android.view.inputmethod.InputMethodSubtype;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;
import java.security.GeneralSecurityException;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import juloo.cdict.Cdict;
import juloo.keyboard2.dict.Dictionaries;
import juloo.keyboard2.dict.DictionariesActivity;
import juloo.keyboard2.ironkeys.IronKeysMessageCipher;
import juloo.keyboard2.ironkeys.IronKeysPrivateKey;
import juloo.keyboard2.ironkeys.IronKeysPrivateKeyStore;
import juloo.keyboard2.ironkeys.IronKeysPublicKey;
import juloo.keyboard2.ironkeys.IronKeysPublicKeyStore;
import juloo.keyboard2.prefs.LayoutsPreference;
import juloo.keyboard2.suggestions.CandidatesView;
import juloo.keyboard2.suggestions.Suggestions;

public class Keyboard2 extends InputMethodService
  implements SharedPreferences.OnSharedPreferenceChangeListener
{
  /** The view containing the keyboard and candidates view. */
  private ViewGroup _keyboard_container_view;
  private Keyboard2View _keyboard_layout_view;
  private CandidatesView _candidates_view;
  private KeyEventHandler _keyeventhandler;
  /** If not 'null', the layout to use instead of [_config.current_layout]. */
  private KeyboardData _currentSpecialLayout;
  /** Layout associated with the currently selected locale. Not 'null'. */
  private KeyboardData _localeTextLayout;
  /** Installed and current locales. */
  private Dictionaries _dictionaries;
  private ViewGroup _emojiPane = null;
  private ViewGroup _clipboard_pane = null;
  private ViewGroup _ironKeysEncryptKeysPane = null;
  private IronKeysEncryptionKeySelectionView _ironKeysEncryptKeysView = null;
  private ViewGroup _ironKeysEncryptBar = null;
  private EditText _ironKeysEncryptText = null;
  private Button _ironKeysEncryptKeysButton = null;
  private ProgressBar _ironKeysEncryptProgress = null;
  private boolean _ironKeysEncryptMode = false;
  private boolean _ironKeysEncryptKeysPaneShown = false;
  private boolean _ironKeysEncrypting = false;
  private int _ironKeysInputSessionId = 0;
  private int _ironKeysEncryptOperationId = 0;
  private String _ironKeysDraftText = "";
  private String _ironKeysSelectedPrivateKeyId = null;
  private Set<String> _ironKeysSelectedPublicKeyIds = new HashSet<String>();
  private Handler _handler;

  private Config _config;

  private FoldStateTracker _foldStateTracker;

  /** Layout currently visible before it has been modified. */
  KeyboardData current_layout_unmodified()
  {
    if (_currentSpecialLayout != null)
      return _currentSpecialLayout;
    KeyboardData layout = null;
    int layout_i = _config.get_current_layout();
    if (layout_i >= _config.layouts.size())
      layout_i = 0;
    if (layout_i < _config.layouts.size())
      layout = _config.layouts.get(layout_i);
    if (layout == null)
      layout = _localeTextLayout;
    return layout;
  }

  /** Layout currently visible. */
  KeyboardData current_layout()
  {
    if (_currentSpecialLayout != null)
      return _currentSpecialLayout;
    return LayoutModifier.modify_layout(current_layout_unmodified());
  }

  void setTextLayout(int l)
  {
    _config.set_current_layout(l);
    _currentSpecialLayout = null;
    _keyboard_layout_view.setKeyboard(current_layout());
  }

  void incrTextLayout(int delta)
  {
    int s = _config.layouts.size();
    setTextLayout((_config.get_current_layout() + delta + s) % s);
  }

  void setSpecialLayout(KeyboardData l)
  {
    _currentSpecialLayout = l;
    _keyboard_layout_view.setKeyboard(l);
  }

  KeyboardData loadLayout(int layout_id)
  {
    return KeyboardData.load(getResources(), layout_id);
  }

  /** Load a layout that contains a numpad. */
  KeyboardData loadNumpad(int layout_id)
  {
    return LayoutModifier.modify_numpad(KeyboardData.load(getResources(), layout_id),
        current_layout_unmodified());
  }

  KeyboardData loadPinentry(int layout_id)
  {
    return LayoutModifier.modify_pinentry(KeyboardData.load(getResources(), layout_id),
        current_layout_unmodified());
  }

  @Override
  public void onCreate()
  {
    super.onCreate();
    SharedPreferences prefs = DirectBootAwarePreferences.get_shared_preferences(this);
    _handler = new Handler(getMainLooper());
    _foldStateTracker = new FoldStateTracker(this);
    _dictionaries = Dictionaries.instance(this);
    Config.initGlobalConfig(prefs, getResources(),
        _foldStateTracker.isUnfolded(), _dictionaries);
    _config = Config.globalConfig();
    _keyeventhandler = new KeyEventHandler(this.new Receiver(), _config);
    _config.handler = _keyeventhandler;
    prefs.registerOnSharedPreferenceChangeListener(this);
    Logs.set_debug_logs(getResources().getBoolean(R.bool.debug_logs));
    refreshSubtypeImm();
    create_keyboard_view();
    ClipboardHistoryService.on_startup(this, _keyeventhandler);
    _foldStateTracker.setChangedCallback(() -> { refresh_config(); });
  }

  @Override
  public void onDestroy() {
    super.onDestroy();

    _foldStateTracker.close();
  }

  private void create_keyboard_view()
  {
    _keyboard_container_view = (ViewGroup)inflate_view(R.layout.keyboard);
    _keyboard_layout_view = (Keyboard2View)_keyboard_container_view.findViewById(R.id.keyboard_view);
    _candidates_view = (CandidatesView)_keyboard_container_view.findViewById(R.id.candidates_view);
    _ironKeysEncryptBar = (ViewGroup)_keyboard_container_view.findViewById(
        R.id.ironkeys_encrypt_bar);
    _ironKeysEncryptText = (EditText)_keyboard_container_view.findViewById(
        R.id.ironkeys_encrypt_text);
    _ironKeysEncryptKeysButton = (Button)_keyboard_container_view.findViewById(
        R.id.ironkeys_encrypt_keys_button);
    _ironKeysEncryptProgress = (ProgressBar)_keyboard_container_view.findViewById(
        R.id.ironkeys_encrypt_progress);
    init_ironkeys_encrypt_bar();
    refresh_ironkeys_encrypt_bar_visibility();
    refresh_ironkeys_encrypt_busy_state();
  }

  private void init_ironkeys_encrypt_bar()
  {
    if (_ironKeysEncryptText == null || _ironKeysEncryptKeysButton == null)
      return;
    _ironKeysDraftText = trim_ironkeys_encrypt_text(_ironKeysDraftText);
    _ironKeysEncryptText.setText(_ironKeysDraftText);
    _ironKeysEncryptText.addTextChangedListener(new TextWatcher() {
      @Override
      public void beforeTextChanged(CharSequence _s, int _start, int _count,
          int _after) {}

      @Override
      public void onTextChanged(CharSequence s, int _start, int _before,
          int _count)
      {
        _ironKeysDraftText = trim_ironkeys_encrypt_text(s.toString());
      }

      @Override
      public void afterTextChanged(Editable s)
      {
        if (s.length() > IronKeysMessageCipher.MAX_PLAINTEXT_CHARS)
          s.delete(IronKeysMessageCipher.MAX_PLAINTEXT_CHARS, s.length());
      }
    });
    _ironKeysEncryptText.setOnEditorActionListener(
        new TextView.OnEditorActionListener() {
      @Override
      public boolean onEditorAction(TextView _view, int actionId,
          KeyEvent event)
      {
        boolean enterPressed = event != null &&
          event.getKeyCode() == KeyEvent.KEYCODE_ENTER &&
          event.getAction() == KeyEvent.ACTION_UP;
        if (actionId == EditorInfo.IME_ACTION_DONE || enterPressed)
        {
          submit_ironkeys_encrypted_message();
          return true;
        }
        return false;
      }
    });
    _ironKeysEncryptKeysButton.setOnClickListener(new View.OnClickListener() {
      @Override
      public void onClick(View _view)
      {
        toggle_ironkeys_encrypt_keys_pane();
      }
    });
  }

  InputMethodManager get_imm()
  {
    return (InputMethodManager)getSystemService(INPUT_METHOD_SERVICE);
  }

  private void refreshSubtypeImm()
  {
    _config.shouldOfferVoiceTyping = true;
    KeyboardData default_layout = null;
    _config.device_locales = DeviceLocales.load(this);
    if (_config.device_locales.default_ != null)
    {
      String layout_name = _config.device_locales.default_.default_layout;
      if (layout_name != null)
        default_layout = LayoutsPreference.layout_of_string(getResources(), layout_name);
    }
    _config.extra_keys_subtype = _config.device_locales.extra_keys();
    if (default_layout == null)
      default_layout = loadLayout(R.xml.latn_qwerty_us);
    _localeTextLayout = default_layout;
  }

  private void refresh_current_dictionary()
  {
    _config.current_dictionary = null;
    _config.emoji_dictionary = null;
    if (_config.device_locales.default_ == null)
      return;
    String current = _config.device_locales.default_.dictionary;
    if (current == null)
      return;
    Cdict[] dicts = _dictionaries.load(current);
    if (dicts == null)
      return;
    _config.current_dictionary = Dictionaries.find_by_name(dicts, "main");
    _config.emoji_dictionary = Dictionaries.find_by_name(dicts, "emoji");
  }

  private void refresh_candidates_view()
  {
    boolean should_show =
      _config.suggestions_enabled
      && _config.editor_config.should_show_candidates_view;
    if (should_show)
      _candidates_view.refresh_config(_config);
    _candidates_view.setVisibility(should_show ? View.VISIBLE : View.GONE);
  }

  /** Might re-create the keyboard view. [_keyboard_layout_view.setKeyboard()] and
      [setInputView()] must be called soon after. */
  private void refresh_config()
  {
    int prev_theme = _config.theme;
    _config.refresh(getResources(), _foldStateTracker.isUnfolded(), _dictionaries);
    refresh_current_dictionary();
    // Refreshing the theme config requires re-creating the views
    if (prev_theme != _config.theme)
    {
      create_keyboard_view();
      _emojiPane = null;
      _clipboard_pane = null;
      _ironKeysEncryptKeysPane = null;
      _ironKeysEncryptKeysView = null;
      setInputView(_keyboard_container_view);
    }
    // Set keyboard background opacity
    Drawable bg = _keyboard_container_view.getBackground().mutate();
    bg.setAlpha(_config.keyboardOpacity);
    _keyboard_container_view.setBackground(bg);
    _keyboard_layout_view.reset();
    refresh_candidates_view();
  }

  private KeyboardData refresh_special_layout()
  {
    if (_config.editor_config.numeric_layout)
    {
      switch (_config.selected_number_layout)
      {
        case PIN: return loadPinentry(R.xml.pin);
        case NUMBER: return loadNumpad(R.xml.numeric);
      }
    }
    return null;
  }

  @Override
  public void onStartInput(EditorInfo attribute, boolean restarting)
  {
    super.onStartInput(attribute, restarting);
    invalidate_ironkeys_encrypt_operation();
  }

  @Override
  public void onStartInputView(EditorInfo info, boolean restarting)
  {
    _config.editor_config.refresh(info, getResources());
    refresh_config();
    _currentSpecialLayout = refresh_special_layout();
    _keyboard_layout_view.setKeyboard(current_layout());
    _keyeventhandler.started(_config);
    set_ironkeys_encrypt_mode(false);
    setInputView(_keyboard_container_view);
    Logs.debug_startup_input_view(info, _config);
  }

  @Override
  public void setInputView(View v)
  {
    ViewParent parent = v.getParent();
    if (parent != null && parent instanceof ViewGroup)
      ((ViewGroup)parent).removeView(v);
    super.setInputView(v);
    if (_ironKeysEncryptKeysPane == null || v != _ironKeysEncryptKeysPane)
      _ironKeysEncryptKeysPaneShown = false;
    updateSoftInputWindowLayoutParams();
    v.requestApplyInsets();
  }

  @Override
  public void updateFullscreenMode() {
    super.updateFullscreenMode();
    updateSoftInputWindowLayoutParams();
  }

  private void updateSoftInputWindowLayoutParams() {
    final Window window = getWindow().getWindow();
    // On API >= 35, Keyboard2View behaves as edge-to-edge
    // APIs 30 to 34 have visual artifact when edge-to-edge is enabled
    if (VERSION.SDK_INT >= 35)
    {
      WindowManager.LayoutParams wattrs = window.getAttributes();
      wattrs.layoutInDisplayCutoutMode =
        WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS;
      // Allow to draw behind system bars
      wattrs.setFitInsetsTypes(0);
      window.setDecorFitsSystemWindows(false);
    }
    updateLayoutHeightOf(window, ViewGroup.LayoutParams.MATCH_PARENT);
    final View inputArea = window.findViewById(android.R.id.inputArea);

    updateLayoutHeightOf(
            (View) inputArea.getParent(),
            isFullscreenMode()
                    ? ViewGroup.LayoutParams.MATCH_PARENT
                    : ViewGroup.LayoutParams.WRAP_CONTENT);
    updateLayoutGravityOf((View) inputArea.getParent(), Gravity.BOTTOM);

  }

  private static void updateLayoutHeightOf(final Window window, final int layoutHeight) {
    final WindowManager.LayoutParams params = window.getAttributes();
    if (params != null && params.height != layoutHeight) {
      params.height = layoutHeight;
      window.setAttributes(params);
    }
  }

  private static void updateLayoutHeightOf(final View view, final int layoutHeight) {
    final ViewGroup.LayoutParams params = view.getLayoutParams();
    if (params != null && params.height != layoutHeight) {
      params.height = layoutHeight;
      view.setLayoutParams(params);
    }
  }

  private static void updateLayoutGravityOf(final View view, final int layoutGravity) {
    final ViewGroup.LayoutParams lp = view.getLayoutParams();
    if (lp instanceof LinearLayout.LayoutParams) {
      final LinearLayout.LayoutParams params = (LinearLayout.LayoutParams) lp;
      if (params.gravity != layoutGravity) {
        params.gravity = layoutGravity;
        view.setLayoutParams(params);
      }
    } else if (lp instanceof FrameLayout.LayoutParams) {
      final FrameLayout.LayoutParams params = (FrameLayout.LayoutParams) lp;
      if (params.gravity != layoutGravity) {
        params.gravity = layoutGravity;
        view.setLayoutParams(params);
      }
    }
  }

  @Override
  public void onCurrentInputMethodSubtypeChanged(InputMethodSubtype subtype)
  {
    refreshSubtypeImm();
    refresh_current_dictionary();
    refresh_candidates_view();
    _keyboard_layout_view.setKeyboard(current_layout());
    _keyeventhandler.ime_subtype_changed();
  }

  @Override
  public void onUpdateSelection(int oldSelStart, int oldSelEnd, int newSelStart, int newSelEnd, int candidatesStart, int candidatesEnd)
  {
    super.onUpdateSelection(oldSelStart, oldSelEnd, newSelStart, newSelEnd, candidatesStart, candidatesEnd);
    _keyeventhandler.selection_updated(oldSelStart, newSelStart, newSelEnd);
    if ((oldSelStart == oldSelEnd) != (newSelStart == newSelEnd))
      _keyboard_layout_view.set_selection_state(newSelStart != newSelEnd);
  }

  @Override
  public void onFinishInputView(boolean finishingInput)
  {
    super.onFinishInputView(finishingInput);
    invalidate_ironkeys_encrypt_operation();
    _keyboard_layout_view.reset();
    set_ironkeys_encrypt_mode(false);
  }

  private void set_ironkeys_encrypt_mode(boolean enabled)
  {
    _ironKeysEncryptMode = enabled;
    if (!enabled && _ironKeysEncryptKeysPaneShown)
      close_ironkeys_encrypt_keys_pane();
    refresh_ironkeys_encrypt_bar_visibility();
    if (enabled && _ironKeysEncryptText != null)
      _ironKeysEncryptText.requestFocus();
  }

  private void toggle_ironkeys_encrypt_mode()
  {
    if (!_ironKeysEncryptMode)
      set_ironkeys_encrypt_mode(true);
    else if (_ironKeysEncryptKeysPaneShown)
      close_ironkeys_encrypt_keys_pane();
    else
      set_ironkeys_encrypt_mode(false);
  }

  private void refresh_ironkeys_encrypt_bar_visibility()
  {
    if (_ironKeysEncryptBar == null)
      return;
    _ironKeysEncryptBar.setVisibility(
        _ironKeysEncryptMode ? View.VISIBLE : View.GONE);
  }

  private void toggle_ironkeys_encrypt_keys_pane()
  {
    if (!_ironKeysEncryptMode)
      set_ironkeys_encrypt_mode(true);
    if (_ironKeysEncryptKeysPaneShown)
      close_ironkeys_encrypt_keys_pane();
    else
      open_ironkeys_encrypt_keys_pane();
  }

  private void open_ironkeys_encrypt_keys_pane()
  {
    if (_ironKeysEncryptKeysPane == null)
    {
      _ironKeysEncryptKeysPane =
          (ViewGroup)inflate_view(R.layout.ironkeys_encrypt_keys_pane);
      _ironKeysEncryptKeysView =
          (IronKeysEncryptionKeySelectionView)_ironKeysEncryptKeysPane
          .findViewById(R.id.ironkeys_encrypt_keys_view);
      _ironKeysEncryptKeysView.setCallback(
          new IronKeysEncryptionKeySelectionView.Callback() {
        @Override
        public void ironKeysEncryptionSelectionChanged(String privateKeyId,
            Set<String> publicKeyIds)
        {
          _ironKeysSelectedPrivateKeyId = privateKeyId;
          _ironKeysSelectedPublicKeyIds = publicKeyIds;
        }
      });
    }
    _ironKeysEncryptKeysView.setSelection(_ironKeysSelectedPrivateKeyId,
        _ironKeysSelectedPublicKeyIds);
    _ironKeysEncryptKeysView.refreshFromStores();
    _ironKeysSelectedPrivateKeyId =
        _ironKeysEncryptKeysView.selectedPrivateKeyId();
    _ironKeysSelectedPublicKeyIds =
        _ironKeysEncryptKeysView.selectedPublicKeyIds();
    _ironKeysEncryptKeysPaneShown = true;
    setInputView(_ironKeysEncryptKeysPane);
  }

  private void close_ironkeys_encrypt_keys_pane()
  {
    _ironKeysEncryptKeysPaneShown = false;
    setInputView(_keyboard_container_view);
    if (_ironKeysEncryptText != null)
      _ironKeysEncryptText.requestFocus();
  }

  private boolean handle_ironkeys_encrypt_text_key(KeyValue key)
  {
    if (!_ironKeysEncryptMode || _ironKeysEncryptKeysPaneShown ||
        _ironKeysEncryptText == null)
      return false;
    if (_ironKeysEncrypting)
      return is_ironkeys_encrypt_text_key(key);
    switch (key.getKind())
    {
      case Char:
        insert_ironkeys_encrypt_text(String.valueOf(key.getChar()));
        return true;
      case String:
        insert_ironkeys_encrypt_text(key.getString());
        return true;
      case Keyevent:
        switch (key.getKeyevent())
        {
          case KeyEvent.KEYCODE_ENTER:
            submit_ironkeys_encrypted_message();
            return true;
          case KeyEvent.KEYCODE_DEL:
            delete_ironkeys_encrypt_text_before_cursor();
            return true;
          case KeyEvent.KEYCODE_FORWARD_DEL:
            delete_ironkeys_encrypt_text_after_cursor();
            return true;
          default:
            return false;
        }
      case Event:
        switch (key.getEvent())
        {
          case ACTION:
            submit_ironkeys_encrypted_message();
            return true;
          default:
            return false;
        }
      case Editing:
        switch (key.getEditing())
        {
          case SPACE_BAR:
            insert_ironkeys_encrypt_text(" ");
            return true;
          case BACKSPACE:
            delete_ironkeys_encrypt_text_before_cursor();
            return true;
          default:
            return false;
        }
      default:
        return false;
    }
  }

  private boolean is_ironkeys_encrypt_text_key(KeyValue key)
  {
    switch (key.getKind())
    {
      case Char:
      case String:
        return true;
      case Keyevent:
        switch (key.getKeyevent())
        {
          case KeyEvent.KEYCODE_ENTER:
          case KeyEvent.KEYCODE_DEL:
          case KeyEvent.KEYCODE_FORWARD_DEL:
            return true;
          default:
            return false;
        }
      case Event:
        return key.getEvent() == KeyValue.Event.ACTION;
      case Editing:
        switch (key.getEditing())
        {
          case SPACE_BAR:
          case BACKSPACE:
            return true;
          default:
            return false;
        }
      default:
        return false;
    }
  }

  private void insert_ironkeys_encrypt_text(String text)
  {
    if (text == null || text.length() == 0)
      return;
    Editable editable = _ironKeysEncryptText.getText();
    int start = normalized_ironkeys_encrypt_selection_start(editable);
    int end = normalized_ironkeys_encrypt_selection_end(editable);
    int replacementBudget = IronKeysMessageCipher.MAX_PLAINTEXT_CHARS -
        (editable.length() - (end - start));
    if (replacementBudget <= 0)
      return;
    editable.replace(start, end,
        trim_ironkeys_encrypt_text(text, replacementBudget));
  }

  private void delete_ironkeys_encrypt_text_before_cursor()
  {
    Editable editable = _ironKeysEncryptText.getText();
    int start = normalized_ironkeys_encrypt_selection_start(editable);
    int end = normalized_ironkeys_encrypt_selection_end(editable);
    if (start != end)
    {
      editable.delete(start, end);
      return;
    }
    if (start <= 0)
      return;
    int deleteStart = start - 1;
    if (deleteStart > 0 &&
        Character.isLowSurrogate(editable.charAt(deleteStart)) &&
        Character.isHighSurrogate(editable.charAt(deleteStart - 1)))
      deleteStart--;
    editable.delete(deleteStart, start);
  }

  private void delete_ironkeys_encrypt_text_after_cursor()
  {
    Editable editable = _ironKeysEncryptText.getText();
    int start = normalized_ironkeys_encrypt_selection_start(editable);
    int end = normalized_ironkeys_encrypt_selection_end(editable);
    if (start != end)
    {
      editable.delete(start, end);
      return;
    }
    if (end >= editable.length())
      return;
    int deleteEnd = end + 1;
    if (deleteEnd < editable.length() &&
        Character.isHighSurrogate(editable.charAt(end)) &&
        Character.isLowSurrogate(editable.charAt(deleteEnd)))
      deleteEnd++;
    editable.delete(end, deleteEnd);
  }

  private int normalized_ironkeys_encrypt_selection_start(Editable editable)
  {
    int start = _ironKeysEncryptText.getSelectionStart();
    int end = _ironKeysEncryptText.getSelectionEnd();
    if (start < 0 || end < 0)
      return editable.length();
    return Math.min(start, end);
  }

  private int normalized_ironkeys_encrypt_selection_end(Editable editable)
  {
    int start = _ironKeysEncryptText.getSelectionStart();
    int end = _ironKeysEncryptText.getSelectionEnd();
    if (start < 0 || end < 0)
      return editable.length();
    return Math.max(start, end);
  }

  private void submit_ironkeys_encrypted_message()
  {
    if (_ironKeysEncrypting)
      return;
    final String plaintext = trim_ironkeys_encrypt_text(_ironKeysDraftText);
    if (!_ironKeysDraftText.equals(plaintext))
    {
      _ironKeysDraftText = plaintext;
      if (_ironKeysEncryptText != null)
      {
        _ironKeysEncryptText.setText(plaintext);
        _ironKeysEncryptText.setSelection(_ironKeysEncryptText.length());
      }
    }
    if (plaintext == null || plaintext.length() == 0)
    {
      show_toast(R.string.ironkeys_encrypt_empty_message);
      return;
    }
    final String privateKeyId = _ironKeysSelectedPrivateKeyId;
    if (privateKeyId == null || privateKeyId.length() == 0)
    {
      show_toast(R.string.ironkeys_encrypt_select_private_key);
      return;
    }
    final Set<String> publicKeyIds =
        new HashSet<String>(_ironKeysSelectedPublicKeyIds);
    if (publicKeyIds.size() != 1)
    {
      show_toast(R.string.ironkeys_encrypt_select_single_public_key);
      return;
    }
    if (getCurrentInputConnection() == null)
    {
      show_toast(R.string.ironkeys_encrypt_no_input_connection);
      return;
    }
    final int inputSessionId = _ironKeysInputSessionId;
    final int operationId = ++_ironKeysEncryptOperationId;
    _ironKeysEncrypting = true;
    refresh_ironkeys_encrypt_busy_state();
    new Thread(new Runnable() {
      @Override
      public void run()
      {
        try
        {
          IronKeysPrivateKey privateKey = find_ironkeys_private_key(privateKeyId);
          List<IronKeysPublicKey> publicKeys =
              find_ironkeys_public_keys(publicKeyIds);
          if (privateKey == null)
            throw new GeneralSecurityException("Selected private key not found.");
          if (publicKeys.size() != 1)
            throw new GeneralSecurityException(
                "Selected recipient public key not found.");
          final String encrypted = new IronKeysMessageCipher()
              .encrypt(plaintext, privateKey, publicKeys);
          _handler.post(new Runnable() {
            @Override
            public void run()
            {
              finish_ironkeys_encrypt_success(operationId, inputSessionId,
                  encrypted);
            }
          });
        }
        catch (final Exception e)
        {
          _handler.post(new Runnable() {
            @Override
            public void run()
            {
              finish_ironkeys_encrypt_failure(operationId, inputSessionId, e);
            }
          });
        }
      }
    }, "IronKeys-encrypt-message").start();
  }

  private IronKeysPrivateKey find_ironkeys_private_key(String privateKeyId)
      throws GeneralSecurityException
  {
    List<IronKeysPrivateKey> privateKeys =
        new IronKeysPrivateKeyStore(this).load();
    for (IronKeysPrivateKey privateKey : privateKeys)
      if (privateKey.id.equals(privateKeyId))
        return privateKey;
    return null;
  }

  private List<IronKeysPublicKey> find_ironkeys_public_keys(
      Set<String> publicKeyIds) throws GeneralSecurityException
  {
    List<IronKeysPublicKey> publicKeys =
        new IronKeysPublicKeyStore(this).load();
    List<IronKeysPublicKey> selectedPublicKeys =
        new ArrayList<IronKeysPublicKey>();
    for (IronKeysPublicKey publicKey : publicKeys)
      if (publicKeyIds.contains(publicKey.id))
        selectedPublicKeys.add(publicKey);
    return selectedPublicKeys;
  }

  private void finish_ironkeys_encrypt_success(int operationId,
      int inputSessionId, String encrypted)
  {
    if (!is_current_ironkeys_encrypt_operation(operationId, inputSessionId))
      return;
    InputConnection conn = getCurrentInputConnection();
    _ironKeysEncrypting = false;
    refresh_ironkeys_encrypt_busy_state();
    if (conn == null)
    {
      show_toast(R.string.ironkeys_encrypt_no_input_connection);
      return;
    }
    conn.commitText(encrypted, 1);
    _ironKeysDraftText = "";
    if (_ironKeysEncryptText != null)
      _ironKeysEncryptText.setText("");
    show_toast(R.string.ironkeys_encrypt_inserted);
  }

  private void finish_ironkeys_encrypt_failure(int operationId,
      int inputSessionId, Exception e)
  {
    if (!is_current_ironkeys_encrypt_operation(operationId, inputSessionId))
      return;
    _ironKeysEncrypting = false;
    refresh_ironkeys_encrypt_busy_state();
    Logs.exn("IronKeys message encryption failed", e);
    show_ironkeys_encrypt_failure(e);
  }

  private void invalidate_ironkeys_encrypt_operation()
  {
    _ironKeysInputSessionId++;
    _ironKeysEncryptOperationId++;
    if (_ironKeysEncrypting)
    {
      _ironKeysEncrypting = false;
      refresh_ironkeys_encrypt_busy_state();
    }
  }

  private boolean is_current_ironkeys_encrypt_operation(int operationId,
      int inputSessionId)
  {
    return _ironKeysEncrypting &&
        _ironKeysEncryptOperationId == operationId &&
        _ironKeysInputSessionId == inputSessionId;
  }

  private void refresh_ironkeys_encrypt_busy_state()
  {
    if (_ironKeysEncryptText != null)
      _ironKeysEncryptText.setEnabled(!_ironKeysEncrypting);
    if (_ironKeysEncryptKeysButton != null)
    {
      _ironKeysEncryptKeysButton.setEnabled(!_ironKeysEncrypting);
      _ironKeysEncryptKeysButton.setVisibility(
          _ironKeysEncrypting ? View.GONE : View.VISIBLE);
    }
    if (_ironKeysEncryptProgress != null)
      _ironKeysEncryptProgress.setVisibility(
          _ironKeysEncrypting ? View.VISIBLE : View.GONE);
  }

  private void show_toast(int resId)
  {
    Toast.makeText(this, resId, Toast.LENGTH_SHORT).show();
  }

  private void show_ironkeys_encrypt_failure(Exception e)
  {
    String message = e.getMessage();
    if (message == null || message.trim().isEmpty())
      message = getString(R.string.ironkeys_encrypt_failed);
    else
      message = getString(R.string.ironkeys_encrypt_failed_with_reason,
          message);
    Toast.makeText(this, message, Toast.LENGTH_LONG).show();
  }

  private static String trim_ironkeys_encrypt_text(String text)
  {
    return trim_ironkeys_encrypt_text(text,
        IronKeysMessageCipher.MAX_PLAINTEXT_CHARS);
  }

  private static String trim_ironkeys_encrypt_text(String text, int maxChars)
  {
    if (text == null)
      return "";
    if (maxChars <= 0)
      return "";
    if (text.length() <= maxChars)
      return text;
    int end = Math.min(maxChars, text.length());
    if (end > 0 && end < text.length() &&
        Character.isHighSurrogate(text.charAt(end - 1)) &&
        Character.isLowSurrogate(text.charAt(end)))
      end--;
    return text.substring(0, end);
  }

  @Override
  public void onSharedPreferenceChanged(SharedPreferences _prefs, String _key)
  {
    refresh_config();
    _keyboard_layout_view.setKeyboard(current_layout());
  }

  @Override
  public boolean onEvaluateFullscreenMode()
  {
    /* Entirely disable fullscreen mode. */
    return false;
  }

  @Override
  public boolean onEvaluateInputViewShown()
  {
    // Since Android 16, this method returns [false] for unknown reasons.
    if (super.onEvaluateInputViewShown())
      return true;
    if (getResources().getConfiguration().hardKeyboardHidden
        == Configuration.HARDKEYBOARDHIDDEN_NO)
    {
      Logs.debug("Physical keyboard is present");
      return false;
    }
    return true;
  }

  /** Called from [onClick] attributes. */
  public void launch_dictionaries_activity(View v)
  {
    start_activity(DictionariesActivity.class);
  }

  void start_activity(Class cls)
  {
    Intent intent = new Intent(this, cls);
    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
    startActivity(intent);
  }

  /** Not static */
  public class Receiver implements KeyEventHandler.IReceiver
  {
    public void handle_event_key(KeyValue.Event ev)
    {
      switch (ev)
      {
        case CONFIG:
          start_activity(SettingsActivity.class);
          break;

        case SWITCH_TEXT:
          _currentSpecialLayout = null;
          _keyboard_layout_view.setKeyboard(current_layout());
          break;

        case SWITCH_NUMERIC:
          setSpecialLayout(loadNumpad(R.xml.numeric));
          break;

        case SWITCH_EMOJI:
          _ironKeysEncryptKeysPaneShown = false;
          if (_emojiPane == null)
            _emojiPane = (ViewGroup)inflate_view(R.layout.emoji_pane);
          setInputView(_emojiPane);
          break;

        case SWITCH_CLIPBOARD:
          _ironKeysEncryptKeysPaneShown = false;
          if (_clipboard_pane == null)
            _clipboard_pane = (ViewGroup)inflate_view(R.layout.clipboard_pane);
          setInputView(_clipboard_pane);
          break;

        case SWITCH_BACK_EMOJI:
        case SWITCH_BACK_CLIPBOARD:
          setInputView(_keyboard_container_view);
          break;

        case SWITCH_BACK_IRONKEYS_ENCRYPT:
          close_ironkeys_encrypt_keys_pane();
          break;

        case CHANGE_METHOD_PICKER:
          get_imm().showInputMethodPicker();
          break;

        case CHANGE_METHOD_PREV:
          if (VERSION.SDK_INT < 28)
            get_imm().switchToLastInputMethod(getConnectionToken());
          else
            switchToPreviousInputMethod();
          break;

        case CHANGE_METHOD_NEXT:
          if (VERSION.SDK_INT < 28)
            get_imm().switchToNextInputMethod(getConnectionToken(), false);
          else
            switchToNextInputMethod(false);
          break;

        case ACTION:
          InputConnection conn = getCurrentInputConnection();
          if (conn != null)
            conn.performEditorAction(_config.editor_config.actionId);
          break;

        case SWITCH_FORWARD:
          incrTextLayout(1);
          break;

        case SWITCH_BACKWARD:
          incrTextLayout(-1);
          break;

        case SWITCH_GREEKMATH:
          setSpecialLayout(loadNumpad(R.xml.greekmath));
          break;

        case CAPS_LOCK:
          set_shift_state(true, true);
          break;

        case SWITCH_VOICE_TYPING:
          if (!VoiceImeSwitcher.switch_to_voice_ime(Keyboard2.this, get_imm(),
                Config.globalPrefs()))
            _config.shouldOfferVoiceTyping = false;
          break;

        case SWITCH_VOICE_TYPING_CHOOSER:
          VoiceImeSwitcher.choose_voice_ime(Keyboard2.this, get_imm(),
              Config.globalPrefs());
          break;

        case ENCRYPT:
          toggle_ironkeys_encrypt_mode();
          break;

        case DECRYPT:
          break;
      }
    }

    public void set_shift_state(boolean state, boolean lock)
    {
      _keyboard_layout_view.set_shift_state(state, lock);
    }

    public void set_compose_pending(boolean pending)
    {
      _keyboard_layout_view.set_compose_pending(pending);
    }

    public void selection_state_changed(boolean selection_is_ongoing)
    {
      _keyboard_layout_view.set_selection_state(selection_is_ongoing);
    }

    public boolean handle_internal_text_key(KeyValue key)
    {
      return handle_ironkeys_encrypt_text_key(key);
    }

    public InputConnection getCurrentInputConnection()
    {
      return Keyboard2.this.getCurrentInputConnection();
    }

    public Handler getHandler()
    {
      return _handler;
    }

    public void set_suggestions(Suggestions suggestions)
    {
      _candidates_view.set_candidates(suggestions);
    }
  }

  private IBinder getConnectionToken()
  {
    return getWindow().getWindow().getAttributes().token;
  }

  private View inflate_view(int layout)
  {
    return View.inflate(new ContextThemeWrapper(this, _config.theme), layout, null);
  }
}
