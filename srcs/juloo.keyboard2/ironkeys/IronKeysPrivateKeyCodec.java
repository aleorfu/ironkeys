package juloo.keyboard2.ironkeys;

import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.PrivateKey;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Key;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.jcajce.interfaces.MLKEMKey;
import org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLKEMPublicKey;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;

public final class IronKeysPrivateKeyCodec
{
  private static final String ENTRY_SEPARATOR = "\n";
  private static final String FIELD_SEPARATOR = "\\|";
  private static final String FIELD_JOIN_SEPARATOR = "|";
  private static final String CURRENT_STORAGE_VERSION = "v4";
  private static final String COMPATIBLE_STORAGE_VERSION = "v3";
  private static final String SUPPORTED_ALGORITHM = "HYBRID_P256_MLKEM768";
  private static final String EC_ALGORITHM = "EC";
  private static final String EC_P256_CURVE_NAME = "secp256r1";
  private static final String MLKEM_ALGORITHM = "MLKEM";
  private static final String ECDSA_SIGNATURE_ALGORITHM = "SHA256withECDSA";
  private static final String MLKEM_768_PARAMETER_NAME =
      MLKEMParameterSpec.ml_kem_768.getName();
  private static final byte[] EC_KEY_PAIR_CHALLENGE =
      "ironkeys-ec-key-pair-check".getBytes(StandardCharsets.UTF_8);

  private static final int CURRENT_LOCAL_KEY_FIELD_COUNT = 13;
  private static final int COMPATIBLE_PORTABLE_LOCAL_KEY_FIELD_COUNT = 11;
  private static final int VERSION_INDEX = 0;
  private static final int LOCAL_KEY_ID_INDEX = 1;
  private static final int LOCAL_KEY_NAME_INDEX = 2;
  private static final int LOCAL_KEY_KEY_ID_INDEX = 3;
  private static final int LOCAL_KEY_ALGORITHM_INDEX = 4;
  private static final int LOCAL_KEY_EC_PUBLIC_KEY_INDEX = 5;
  private static final int LOCAL_KEY_EC_PRIVATE_KEY_INDEX = 6;
  private static final int LOCAL_KEY_MLKEM_PUBLIC_KEY_INDEX = 7;
  private static final int LOCAL_KEY_MLKEM_PRIVATE_KEY_INDEX = 8;
  private static final int LOCAL_KEY_FINGERPRINT_INDEX = 9;
  private static final int LOCAL_KEY_CREATED_AT_INDEX = 10;
  private static final int LOCAL_KEY_EC_KEYSTORE_ALIAS_INDEX = 11;
  private static final int LOCAL_KEY_MLKEM_WRAP_ALIAS_INDEX = 12;

  private static final int BACKUP_FIELD_COUNT = 5;
  private static final int BACKUP_VERSION_INDEX = 0;
  private static final int BACKUP_SELECTED_LOCAL_KEY_ID_INDEX = 1;
  private static final int BACKUP_LOCAL_KEYS_INDEX = 3;
  private static final String BACKUP_VERSION = "1";

  public String encodeBackup(List<IronKeysPrivateKey> privateKeys,
      String selectedLocalKeyId)
  {
    return encodeFields(
        BACKUP_VERSION,
        selectedLocalKeyId == null ? "" : selectedLocalKeyId,
        "",
        encodeLocalKeys(privateKeys),
        "");
  }

  public List<IronKeysPrivateKey> decodeImport(String rawValue)
  {
    String trimmed = rawValue == null ? "" : rawValue.trim();
    if (trimmed.isEmpty())
      return new ArrayList<IronKeysPrivateKey>();

    List<IronKeysPrivateKey> backupKeys = decodeBackup(trimmed);
    if (!backupKeys.isEmpty())
      return backupKeys;

    return decodeLocalKeys(trimmed, true);
  }

  public String encodeLocalKeys(List<IronKeysPrivateKey> privateKeys)
  {
    List<String> encodedKeys = new ArrayList<String>();
    for (IronKeysPrivateKey privateKey : privateKeys)
    {
      encodedKeys.add(encodeFields(
          CURRENT_STORAGE_VERSION,
          privateKey.id,
          privateKey.name,
          privateKey.keyId,
          privateKey.algorithm,
          privateKey.ecPublicKeyBase64,
          privateKey.ecPrivateKeyBase64,
          privateKey.mlKemPublicKeyBase64,
          privateKey.mlKemPrivateKeyBase64,
          privateKey.fingerprint,
          Long.toString(privateKey.createdAtEpochMillis),
          "",
          ""));
    }
    return join(encodedKeys, ENTRY_SEPARATOR);
  }

  public List<IronKeysPrivateKey> decodeLocalKeys(String rawValue)
  {
    return decodeLocalKeys(rawValue, false);
  }

  private List<IronKeysPrivateKey> decodeLocalKeys(String rawValue,
      boolean strict)
  {
    List<IronKeysPrivateKey> privateKeys = new ArrayList<IronKeysPrivateKey>();
    if (rawValue == null)
      return privateKeys;
    String[] lines = rawValue.split("\\r?\\n");
    for (String line : lines)
    {
      String trimmed = line.trim();
      if (trimmed.isEmpty())
        continue;
      List<String> fields = decodeFields(trimmed);
      IronKeysPrivateKey privateKey = decodeLocalKeyFields(fields, strict);
      if (privateKey == null && strict)
        return new ArrayList<IronKeysPrivateKey>();
      if (privateKey != null)
        privateKeys.add(privateKey);
    }
    return privateKeys;
  }

  private List<IronKeysPrivateKey> decodeBackup(String rawValue)
  {
    List<String> fields = decodeFields(rawValue);
    if (fields.size() != BACKUP_FIELD_COUNT ||
        !BACKUP_VERSION.equals(fields.get(BACKUP_VERSION_INDEX)))
      return new ArrayList<IronKeysPrivateKey>();

    List<IronKeysPrivateKey> privateKeys =
        decodeLocalKeys(fields.get(BACKUP_LOCAL_KEYS_INDEX), true);
    String selectedLocalKeyId = fields.get(BACKUP_SELECTED_LOCAL_KEY_ID_INDEX);
    if (selectedLocalKeyId == null || selectedLocalKeyId.isEmpty())
      return privateKeys;

    List<IronKeysPrivateKey> ordered = new ArrayList<IronKeysPrivateKey>();
    for (IronKeysPrivateKey privateKey : privateKeys)
      if (selectedLocalKeyId.equals(privateKey.id))
        ordered.add(privateKey);
    for (IronKeysPrivateKey privateKey : privateKeys)
      if (!selectedLocalKeyId.equals(privateKey.id))
        ordered.add(privateKey);
    return ordered;
  }

  private IronKeysPrivateKey decodeLocalKeyFields(List<String> fields,
      boolean validateKeyPair)
  {
    if (fields.size() == CURRENT_LOCAL_KEY_FIELD_COUNT &&
        CURRENT_STORAGE_VERSION.equals(fields.get(VERSION_INDEX)))
    {
      if (!SUPPORTED_ALGORITHM.equals(fields.get(LOCAL_KEY_ALGORITHM_INDEX)))
        return null;
      if (!fields.get(LOCAL_KEY_EC_KEYSTORE_ALIAS_INDEX).isEmpty() ||
          !fields.get(LOCAL_KEY_MLKEM_WRAP_ALIAS_INDEX).isEmpty())
        return null;
      Long createdAtEpochMillis =
          parseLong(fields.get(LOCAL_KEY_CREATED_AT_INDEX));
      if (createdAtEpochMillis == null)
        return null;
      return validatedLocalKey(
          fields.get(LOCAL_KEY_ID_INDEX),
          fields.get(LOCAL_KEY_NAME_INDEX),
          fields.get(LOCAL_KEY_KEY_ID_INDEX),
          fields.get(LOCAL_KEY_ALGORITHM_INDEX),
          fields.get(LOCAL_KEY_EC_PUBLIC_KEY_INDEX),
          fields.get(LOCAL_KEY_EC_PRIVATE_KEY_INDEX),
          fields.get(LOCAL_KEY_MLKEM_PUBLIC_KEY_INDEX),
          fields.get(LOCAL_KEY_MLKEM_PRIVATE_KEY_INDEX),
          fields.get(LOCAL_KEY_FINGERPRINT_INDEX),
          createdAtEpochMillis,
          validateKeyPair);
    }

    if (fields.size() == COMPATIBLE_PORTABLE_LOCAL_KEY_FIELD_COUNT &&
        COMPATIBLE_STORAGE_VERSION.equals(fields.get(VERSION_INDEX)))
    {
      if (!SUPPORTED_ALGORITHM.equals(fields.get(LOCAL_KEY_ALGORITHM_INDEX)))
        return null;
      Long createdAtEpochMillis =
          parseLong(fields.get(LOCAL_KEY_CREATED_AT_INDEX));
      if (createdAtEpochMillis == null)
        return null;
      return validatedLocalKey(
          fields.get(LOCAL_KEY_ID_INDEX),
          fields.get(LOCAL_KEY_NAME_INDEX),
          fields.get(LOCAL_KEY_KEY_ID_INDEX),
          fields.get(LOCAL_KEY_ALGORITHM_INDEX),
          fields.get(LOCAL_KEY_EC_PUBLIC_KEY_INDEX),
          fields.get(LOCAL_KEY_EC_PRIVATE_KEY_INDEX),
          fields.get(LOCAL_KEY_MLKEM_PUBLIC_KEY_INDEX),
          fields.get(LOCAL_KEY_MLKEM_PRIVATE_KEY_INDEX),
          fields.get(LOCAL_KEY_FINGERPRINT_INDEX),
          createdAtEpochMillis,
          validateKeyPair);
    }
    return null;
  }

  private IronKeysPrivateKey validatedLocalKey(String id, String name,
      String keyId, String algorithm, String ecPublicKeyBase64,
      String ecPrivateKeyBase64, String mlKemPublicKeyBase64,
      String mlKemPrivateKeyBase64, String fingerprint,
      long createdAtEpochMillis, boolean validateKeyPair)
  {
    if (id.isEmpty() || keyId.isEmpty() || !id.equals(keyId) ||
        createdAtEpochMillis < 0)
      return null;

    byte[] encodedEcPublicKey = decodeBase64(ecPublicKeyBase64);
    byte[] encodedEcPrivateKey = decodeBase64(ecPrivateKeyBase64);
    byte[] encodedMlKemPublicKey = decodeBase64(mlKemPublicKeyBase64);
    byte[] encodedMlKemPrivateKey = decodeBase64(mlKemPrivateKeyBase64);
    if (encodedEcPublicKey == null || encodedEcPrivateKey == null ||
        encodedMlKemPublicKey == null || encodedMlKemPrivateKey == null)
      return null;
    if (validateKeyPair &&
        (!isValidP256EcKeyPair(encodedEcPublicKey, encodedEcPrivateKey) ||
        !isValidMlKem768KeyPair(encodedMlKemPublicKey,
            encodedMlKemPrivateKey)))
      return null;

    String expectedKeyId = IronKeysPrivateKeyMetadata.keyIdForPublicKeyBundle(
        encodedEcPublicKey, encodedMlKemPublicKey);
    String expectedFingerprint =
        IronKeysPrivateKeyMetadata.fingerprintForPublicKeyBundle(
            encodedEcPublicKey, encodedMlKemPublicKey);
    if (!keyId.equals(expectedKeyId) || !fingerprint.equals(expectedFingerprint))
      return null;

    return new IronKeysPrivateKey(
        id,
        name,
        keyId,
        algorithm,
        ecPublicKeyBase64,
        ecPrivateKeyBase64,
        mlKemPublicKeyBase64,
        mlKemPrivateKeyBase64,
        fingerprint,
        createdAtEpochMillis);
  }

  private static byte[] decodeBase64(String value)
  {
    try
    {
      return IronKeysBase64.decode(value);
    }
    catch (IllegalArgumentException e)
    {
      return null;
    }
  }

  private static boolean isValidP256EcKeyPair(byte[] encodedPublicKey,
      byte[] encodedPrivateKey)
  {
    try
    {
      KeyFactory keyFactory = KeyFactory.getInstance(EC_ALGORITHM);
      PublicKey publicKey = keyFactory
          .generatePublic(new X509EncodedKeySpec(encodedPublicKey));
      PrivateKey privateKey = keyFactory
          .generatePrivate(new PKCS8EncodedKeySpec(encodedPrivateKey));
      if (!isP256EcKey(publicKey) || !isP256EcKey(privateKey))
        return false;

      Signature signature = Signature.getInstance(ECDSA_SIGNATURE_ALGORITHM);
      signature.initSign(privateKey);
      signature.update(EC_KEY_PAIR_CHALLENGE);
      byte[] signedChallenge = signature.sign();

      signature.initVerify(publicKey);
      signature.update(EC_KEY_PAIR_CHALLENGE);
      return signature.verify(signedChallenge);
    }
    catch (GeneralSecurityException e)
    {
      return false;
    }
  }

  private static boolean isValidMlKem768KeyPair(byte[] encodedPublicKey,
      byte[] encodedPrivateKey)
  {
    try
    {
      KeyFactory keyFactory = KeyFactory.getInstance(MLKEM_ALGORITHM,
          IronKeysPqcProvider.provider());
      PublicKey publicKey = keyFactory
          .generatePublic(new X509EncodedKeySpec(encodedPublicKey));
      PrivateKey privateKey = keyFactory
          .generatePrivate(new PKCS8EncodedKeySpec(encodedPrivateKey));
      if (!(publicKey instanceof MLKEMPublicKey) ||
          !(privateKey instanceof MLKEMPrivateKey))
        return false;

      MLKEMPublicKey mlKemPublicKey = (MLKEMPublicKey)publicKey;
      MLKEMPrivateKey mlKemPrivateKey = (MLKEMPrivateKey)privateKey;
      MLKEMPublicKey derivedPublicKey = mlKemPrivateKey.getPublicKey();
      return isMlKem768Key(mlKemPublicKey) &&
          isMlKem768Key(mlKemPrivateKey) &&
          derivedPublicKey != null &&
          isMlKem768Key(derivedPublicKey) &&
          Arrays.equals(mlKemPublicKey.getPublicData(),
              derivedPublicKey.getPublicData());
    }
    catch (GeneralSecurityException e)
    {
      return false;
    }
  }

  private static boolean isMlKem768Key(MLKEMKey key)
  {
    return key.getParameterSpec() != null &&
        MLKEM_768_PARAMETER_NAME.equals(key.getParameterSpec().getName());
  }

  private static boolean isP256EcKey(Key key)
  {
    if (!(key instanceof ECKey))
      return false;
    ECKey ecKey = (ECKey)key;
    ECParameterSpec params = ecKey.getParams();
    if (params == null)
      return false;
    try
    {
      return isSameEcParameterSpec(params, p256EcParameterSpec());
    }
    catch (GeneralSecurityException e)
    {
      return false;
    }
  }

  private static ECParameterSpec p256EcParameterSpec()
      throws GeneralSecurityException
  {
    AlgorithmParameters parameters = AlgorithmParameters.getInstance(EC_ALGORITHM);
    parameters.init(new ECGenParameterSpec(EC_P256_CURVE_NAME));
    return parameters.getParameterSpec(ECParameterSpec.class);
  }

  private static boolean isSameEcParameterSpec(ECParameterSpec first,
      ECParameterSpec second)
  {
    return first.getCurve().equals(second.getCurve()) &&
        first.getGenerator().equals(second.getGenerator()) &&
        first.getOrder().equals(second.getOrder()) &&
        first.getCofactor() == second.getCofactor();
  }

  private String encodeFields(String... fields)
  {
    List<String> encodedFields = new ArrayList<String>();
    for (String field : fields)
      encodedFields.add(IronKeysBase64.encodeUrlString(field == null ? "" : field));
    return join(encodedFields, FIELD_JOIN_SEPARATOR);
  }

  private List<String> decodeFields(String encodedValue)
  {
    List<String> fields = new ArrayList<String>();
    try
    {
      String[] tokens = encodedValue.split(FIELD_SEPARATOR, -1);
      for (String token : tokens)
        fields.add(IronKeysBase64.decodeUrlString(token));
    }
    catch (IllegalArgumentException e)
    {
      fields.clear();
    }
    return fields;
  }

  private static Long parseLong(String value)
  {
    try
    {
      return Long.valueOf(value);
    }
    catch (NumberFormatException e)
    {
      return null;
    }
  }

  private static String join(List<String> values, String separator)
  {
    StringBuilder builder = new StringBuilder();
    for (int i = 0; i < values.size(); i++)
    {
      if (i > 0)
        builder.append(separator);
      builder.append(values.get(i));
    }
    return builder.toString();
  }
}
