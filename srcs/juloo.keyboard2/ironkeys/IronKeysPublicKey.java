package juloo.keyboard2.ironkeys;

public final class IronKeysPublicKey
{
  public final String id;
  public final String name;
  public final String keyId;
  public final String algorithm;
  public final String ecPublicKeyBase64;
  public final String mlKemPublicKeyBase64;
  public final String fingerprint;
  public final long addedAtEpochMillis;

  public IronKeysPublicKey(String id, String name, String keyId,
      String algorithm, String ecPublicKeyBase64, String mlKemPublicKeyBase64,
      String fingerprint, long addedAtEpochMillis)
  {
    this.id = id;
    this.name = name;
    this.keyId = keyId;
    this.algorithm = algorithm;
    this.ecPublicKeyBase64 = ecPublicKeyBase64;
    this.mlKemPublicKeyBase64 = mlKemPublicKeyBase64;
    this.fingerprint = fingerprint;
    this.addedAtEpochMillis = addedAtEpochMillis;
  }

  IronKeysPublicKey withAddedAt(long addedAtEpochMillis)
  {
    return new IronKeysPublicKey(
        id,
        name,
        keyId,
        algorithm,
        ecPublicKeyBase64,
        mlKemPublicKeyBase64,
        fingerprint,
        addedAtEpochMillis);
  }
}
