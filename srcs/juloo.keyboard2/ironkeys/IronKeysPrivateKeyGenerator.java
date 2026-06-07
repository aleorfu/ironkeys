package juloo.keyboard2.ironkeys;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;

public final class IronKeysPrivateKeyGenerator
{
  private static final String ALGORITHM_WIRE_NAME = "HYBRID_P256_MLKEM768";
  private static final String EC_ALGORITHM = "EC";
  private static final String EC_CURVE_NAME = "secp256r1";
  private static final String MLKEM_ALGORITHM = "MLKEM";

  private final SecureRandom _secureRandom;

  public IronKeysPrivateKeyGenerator()
  {
    _secureRandom = new SecureRandom();
  }

  public IronKeysPrivateKey generate(String name)
      throws GeneralSecurityException
  {
    KeyPairGenerator ecGenerator = KeyPairGenerator.getInstance(EC_ALGORITHM);
    ecGenerator.initialize(new ECGenParameterSpec(EC_CURVE_NAME), _secureRandom);
    KeyPair ecKeyPair = ecGenerator.generateKeyPair();

    KeyPairGenerator mlKemGenerator = KeyPairGenerator.getInstance(
        MLKEM_ALGORITHM, IronKeysPqcProvider.provider());
    mlKemGenerator.initialize(MLKEMParameterSpec.ml_kem_768, _secureRandom);
    KeyPair mlKemKeyPair = mlKemGenerator.generateKeyPair();

    byte[] encodedEcPublicKey = ecKeyPair.getPublic().getEncoded();
    byte[] encodedEcPrivateKey = ecKeyPair.getPrivate().getEncoded();
    byte[] encodedMlKemPublicKey = mlKemKeyPair.getPublic().getEncoded();
    byte[] encodedMlKemPrivateKey = mlKemKeyPair.getPrivate().getEncoded();
    if (encodedEcPrivateKey == null || encodedMlKemPrivateKey == null)
      throw new GeneralSecurityException("Private key material is not exportable.");

    String keyId = IronKeysPrivateKeyMetadata.keyIdForPublicKeyBundle(
        encodedEcPublicKey, encodedMlKemPublicKey);
    return new IronKeysPrivateKey(
        keyId,
        name,
        keyId,
        ALGORITHM_WIRE_NAME,
        IronKeysBase64.encode(encodedEcPublicKey),
        IronKeysBase64.encode(encodedEcPrivateKey),
        IronKeysBase64.encode(encodedMlKemPublicKey),
        IronKeysBase64.encode(encodedMlKemPrivateKey),
        IronKeysPrivateKeyMetadata.fingerprintForPublicKeyBundle(
            encodedEcPublicKey, encodedMlKemPublicKey),
        System.currentTimeMillis());
  }
}
