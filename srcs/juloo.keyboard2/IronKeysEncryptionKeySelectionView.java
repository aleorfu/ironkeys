package juloo.keyboard2;

import android.content.Context;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.ScrollView;
import android.widget.TextView;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import juloo.keyboard2.ironkeys.IronKeysPrivateKey;
import juloo.keyboard2.ironkeys.IronKeysPrivateKeyStore;
import juloo.keyboard2.ironkeys.IronKeysPublicKey;
import juloo.keyboard2.ironkeys.IronKeysPublicKeyStore;

public final class IronKeysEncryptionKeySelectionView extends ScrollView
{
  private final LinearLayout _content;
  private final Map<Integer, String> _privateKeyIdsByRadioId =
      new HashMap<Integer, String>();
  private final Map<Integer, String> _publicKeyIdsByRadioId =
      new HashMap<Integer, String>();
  private final Set<String> _selectedPublicKeyIds = new HashSet<String>();
  private String _selectedPrivateKeyId;
  private Callback _callback;
  private boolean _refreshing;

  public IronKeysEncryptionKeySelectionView(Context context, AttributeSet attrs)
  {
    super(context, attrs);
    _content = new LinearLayout(context);
    _content.setOrientation(LinearLayout.VERTICAL);
    _content.setPadding(dp(12), dp(8), dp(12), dp(12));
    addView(_content, new ScrollView.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT));
  }

  public void setCallback(Callback callback)
  {
    _callback = callback;
  }

  public void setSelection(String privateKeyId, Set<String> publicKeyIds)
  {
    _selectedPrivateKeyId = privateKeyId;
    _selectedPublicKeyIds.clear();
    if (publicKeyIds != null)
      setSinglePublicKeyId(firstPublicKeyId(publicKeyIds));
  }

  public String selectedPrivateKeyId()
  {
    return _selectedPrivateKeyId;
  }

  public Set<String> selectedPublicKeyIds()
  {
    return new HashSet<String>(_selectedPublicKeyIds);
  }

  public void refreshFromStores()
  {
    _refreshing = true;
    _content.removeAllViews();
    _privateKeyIdsByRadioId.clear();
    _publicKeyIdsByRadioId.clear();

    if (!IronKeysPrivateKeyStore.isKeystoreSupported())
    {
      addStatus(R.string.ironkeys_private_keys_android_version_unavailable);
      _refreshing = false;
      notifySelectionChanged();
      return;
    }
    if (!IronKeysPrivateKeyStore.isAvailable(getContext()) ||
        !IronKeysPublicKeyStore.isAvailable(getContext()))
    {
      addStatus(R.string.ironkeys_private_keys_locked_unavailable);
      _refreshing = false;
      notifySelectionChanged();
      return;
    }

    try
    {
      List<IronKeysPrivateKey> privateKeys =
          new IronKeysPrivateKeyStore(getContext()).load();
      List<IronKeysPublicKey> publicKeys =
          new IronKeysPublicKeyStore(getContext()).load();
      refreshPrivateKeys(privateKeys);
      refreshPublicKeys(publicKeys);
    }
    catch (Exception e)
    {
      addStatus(R.string.ironkeys_encrypt_keys_read_error);
    }
    _refreshing = false;
    notifySelectionChanged();
  }

  private void refreshPrivateKeys(List<IronKeysPrivateKey> privateKeys)
  {
    addHeading(R.string.ironkeys_encrypt_private_key_heading);
    if (privateKeys.isEmpty())
    {
      _selectedPrivateKeyId = null;
      addStatus(R.string.ironkeys_no_private_keys_summary);
      return;
    }

    if (!containsPrivateKey(privateKeys, _selectedPrivateKeyId))
      _selectedPrivateKeyId = privateKeys.get(0).id;

    RadioGroup group = new RadioGroup(getContext());
    group.setOrientation(RadioGroup.VERTICAL);
    group.setLayoutParams(matchWrapParams());
    for (IronKeysPrivateKey privateKey : privateKeys)
    {
      RadioButton button = new RadioButton(getContext());
      int id = View.generateViewId();
      _privateKeyIdsByRadioId.put(id, privateKey.id);
      button.setId(id);
      button.setText(keyLabel(privateKey.name, privateKey.fingerprint));
      button.setTextColor(colorAttr(R.attr.colorLabel));
      button.setPadding(0, dp(8), 0, dp(8));
      button.setLayoutParams(matchWrapParams());
      group.addView(button);
      if (privateKey.id.equals(_selectedPrivateKeyId))
        button.setChecked(true);
    }
    group.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
      @Override
      public void onCheckedChanged(RadioGroup _group, int checkedId)
      {
        _selectedPrivateKeyId = _privateKeyIdsByRadioId.get(checkedId);
        notifySelectionChanged();
      }
    });
    _content.addView(group);
  }

  private void refreshPublicKeys(List<IronKeysPublicKey> publicKeys)
  {
    addHeading(R.string.ironkeys_encrypt_public_keys_heading);
    if (publicKeys.isEmpty())
    {
      _selectedPublicKeyIds.clear();
      addStatus(R.string.ironkeys_no_public_keys_summary);
      return;
    }

    Set<String> existingKeyIds = new HashSet<String>();
    for (final IronKeysPublicKey publicKey : publicKeys)
      existingKeyIds.add(publicKey.id);
    _selectedPublicKeyIds.retainAll(existingKeyIds);
    setSinglePublicKeyId(firstPublicKeyId(_selectedPublicKeyIds));

    RadioGroup group = new RadioGroup(getContext());
    group.setOrientation(RadioGroup.VERTICAL);
    group.setLayoutParams(matchWrapParams());
    for (final IronKeysPublicKey publicKey : publicKeys)
    {
      RadioButton button = new RadioButton(getContext());
      int id = View.generateViewId();
      _publicKeyIdsByRadioId.put(id, publicKey.id);
      button.setId(id);
      button.setText(keyLabel(publicKey.name, publicKey.fingerprint));
      button.setTextColor(colorAttr(R.attr.colorLabel));
      button.setPadding(0, dp(8), 0, dp(8));
      button.setLayoutParams(matchWrapParams());
      group.addView(button);
      if (_selectedPublicKeyIds.contains(publicKey.id))
        button.setChecked(true);
    }
    group.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
      @Override
      public void onCheckedChanged(RadioGroup _group, int checkedId)
      {
        setSinglePublicKeyId(_publicKeyIdsByRadioId.get(checkedId));
        notifySelectionChanged();
      }
    });
    _content.addView(group);
  }

  private boolean containsPrivateKey(List<IronKeysPrivateKey> keys, String id)
  {
    if (id == null)
      return false;
    for (IronKeysPrivateKey key : keys)
      if (id.equals(key.id))
        return true;
    return false;
  }

  private String keyLabel(String name, String fingerprint)
  {
    String label = name == null ? "" : name.trim();
    if (label.isEmpty())
      label = getContext().getString(R.string.ironkeys_encrypt_unnamed_key);
    return label + "\n" + fingerprint;
  }

  private void setSinglePublicKeyId(String keyId)
  {
    _selectedPublicKeyIds.clear();
    if (keyId != null)
      _selectedPublicKeyIds.add(keyId);
  }

  private String firstPublicKeyId(Set<String> publicKeyIds)
  {
    if (publicKeyIds == null)
      return null;
    for (String publicKeyId : publicKeyIds)
      return publicKeyId;
    return null;
  }

  private void addHeading(int resId)
  {
    TextView heading = new TextView(getContext());
    heading.setText(resId);
    heading.setTextColor(colorAttr(R.attr.colorSubLabel));
    heading.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
    heading.setTypeface(heading.getTypeface(), android.graphics.Typeface.BOLD);
    heading.setPadding(0, dp(12), 0, dp(2));
    heading.setLayoutParams(matchWrapParams());
    _content.addView(heading);
  }

  private void addStatus(int resId)
  {
    TextView status = new TextView(getContext());
    status.setText(resId);
    status.setTextColor(colorAttr(R.attr.colorLabel));
    status.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
    status.setPadding(0, dp(8), 0, dp(8));
    status.setLayoutParams(matchWrapParams());
    _content.addView(status);
  }

  private void notifySelectionChanged()
  {
    if (_refreshing || _callback == null)
      return;
    _callback.ironKeysEncryptionSelectionChanged(_selectedPrivateKeyId,
        selectedPublicKeyIds());
  }

  private LinearLayout.LayoutParams matchWrapParams()
  {
    return new LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT);
  }

  private int colorAttr(int attr)
  {
    TypedValue value = new TypedValue();
    getContext().getTheme().resolveAttribute(attr, value, true);
    return value.data;
  }

  private int dp(int value)
  {
    return (int)(value * getResources().getDisplayMetrics().density + 0.5f);
  }

  public static interface Callback
  {
    public void ironKeysEncryptionSelectionChanged(String privateKeyId,
        Set<String> publicKeyIds);
  }
}
