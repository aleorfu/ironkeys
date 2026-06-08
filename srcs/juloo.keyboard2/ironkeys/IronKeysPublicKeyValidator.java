package juloo.keyboard2.ironkeys;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.jcajce.interfaces.MLKEMKey;
import org.bouncycastle.jcajce.interfaces.MLKEMPublicKey;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;

final class IronKeysPublicKeyValidator
{
  static final String SUPPORTED_ALGORITHM = "HYBRID_P256_MLKEM768";

  private static final String LEGACY_ALGORITHM = "LEGACY_EC_P256";
  private static final String EC_ALGORITHM = "EC";
  private static final String EC_P256_CURVE_NAME = "secp256r1";
  private static final String MLKEM_ALGORITHM = "MLKEM";
  private static final String MLKEM_768_PARAMETER_NAME =
      MLKEMParameterSpec.ml_kem_768.getName();

  private IronKeysPublicKeyValidator() {}

  static ValidationResult validate(String keyId, String algorithm,
      String ecPublicKeyBase64, String mlKemPublicKeyBase64,
      String fingerprint)
  {
    if (LEGACY_ALGORITHM.equals(algorithm))
      return ValidationResult.legacyUnsupported();
    if (!SUPPORTED_ALGORITHM.equals(algorithm))
      return ValidationResult.unsupportedAlgorithm();

    byte[] encodedEcPublicKey = decodeBase64(ecPublicKeyBase64);
    byte[] encodedMlKemPublicKey = decodeBase64(mlKemPublicKeyBase64);
    if (encodedEcPublicKey == null || encodedMlKemPublicKey == null)
      return ValidationResult.invalid();
    if (!isValidP256EcPublicKey(encodedEcPublicKey) ||
        !isValidMlKem768PublicKey(encodedMlKemPublicKey))
      return ValidationResult.invalid();

    String expectedKeyId = IronKeysPrivateKeyMetadata.keyIdForPublicKeyBundle(
        encodedEcPublicKey, encodedMlKemPublicKey);
    String expectedFingerprint =
        IronKeysPrivateKeyMetadata.fingerprintForPublicKeyBundle(
            encodedEcPublicKey, encodedMlKemPublicKey);
    if (!expectedKeyId.equals(keyId) || !expectedFingerprint.equals(fingerprint))
      return ValidationResult.invalid();

    return ValidationResult.success(
        IronKeysBase64.encode(encodedEcPublicKey),
        IronKeysBase64.encode(encodedMlKemPublicKey),
        expectedKeyId,
        expectedFingerprint);
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

  private static boolean isValidP256EcPublicKey(byte[] encodedPublicKey)
  {
    try
    {
      PublicKey publicKey = KeyFactory.getInstance(EC_ALGORITHM)
          .generatePublic(new X509EncodedKeySpec(encodedPublicKey));
      return isP256EcKey(publicKey);
    }
    catch (GeneralSecurityException e)
    {
      return false;
    }
  }

  private static boolean isValidMlKem768PublicKey(byte[] encodedPublicKey)
  {
    try
    {
      PublicKey publicKey = KeyFactory.getInstance(MLKEM_ALGORITHM,
          IronKeysPqcProvider.provider())
          .generatePublic(new X509EncodedKeySpec(encodedPublicKey));
      return publicKey instanceof MLKEMPublicKey &&
          isMlKem768Key((MLKEMPublicKey)publicKey);
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
    AlgorithmParameters parameters =
        AlgorithmParameters.getInstance(EC_ALGORITHM);
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

  static final class ValidationResult
  {
    enum Status
    {
      SUCCESS,
      INVALID,
      UNSUPPORTED_ALGORITHM,
      LEGACY_UNSUPPORTED
    }

    final Status status;
    final String normalizedEcPublicKeyBase64;
    final String normalizedMlKemPublicKeyBase64;
    final String keyId;
    final String fingerprint;

    private ValidationResult(Status status, String normalizedEcPublicKeyBase64,
        String normalizedMlKemPublicKeyBase64, String keyId,
        String fingerprint)
    {
      this.status = status;
      this.normalizedEcPublicKeyBase64 = normalizedEcPublicKeyBase64;
      this.normalizedMlKemPublicKeyBase64 = normalizedMlKemPublicKeyBase64;
      this.keyId = keyId;
      this.fingerprint = fingerprint;
    }

    static ValidationResult success(String normalizedEcPublicKeyBase64,
        String normalizedMlKemPublicKeyBase64, String keyId,
        String fingerprint)
    {
      return new ValidationResult(Status.SUCCESS, normalizedEcPublicKeyBase64,
          normalizedMlKemPublicKeyBase64, keyId, fingerprint);
    }

    static ValidationResult invalid()
    {
      return new ValidationResult(Status.INVALID, null, null, null, null);
    }

    static ValidationResult unsupportedAlgorithm()
    {
      return new ValidationResult(Status.UNSUPPORTED_ALGORITHM, null, null,
          null, null);
    }

    static ValidationResult legacyUnsupported()
    {
      return new ValidationResult(Status.LEGACY_UNSUPPORTED, null, null, null,
          null);
    }
  }
}
