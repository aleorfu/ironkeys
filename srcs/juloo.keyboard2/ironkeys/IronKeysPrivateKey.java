package juloo.keyboard2.ironkeys;

import java.util.Locale;

public final class IronKeysPrivateKey
{
  public final String id;
  public final String name;
  public final String keyId;
  public final String algorithm;
  public final String ecPublicKeyBase64;
  public final String ecPrivateKeyBase64;
  public final String mlKemPublicKeyBase64;
  public final String mlKemPrivateKeyBase64;
  public final String fingerprint;
  public final long createdAtEpochMillis;

  public IronKeysPrivateKey(String id, String name, String keyId,
      String algorithm, String ecPublicKeyBase64, String ecPrivateKeyBase64,
      String mlKemPublicKeyBase64, String mlKemPrivateKeyBase64,
      String fingerprint, long createdAtEpochMillis)
  {
    this.id = id;
    this.name = name;
    this.keyId = keyId;
    this.algorithm = algorithm;
    this.ecPublicKeyBase64 = ecPublicKeyBase64;
    this.ecPrivateKeyBase64 = ecPrivateKeyBase64;
    this.mlKemPublicKeyBase64 = mlKemPublicKeyBase64;
    this.mlKemPrivateKeyBase64 = mlKemPrivateKeyBase64;
    this.fingerprint = fingerprint;
    this.createdAtEpochMillis = createdAtEpochMillis;
  }

  public String safeFileName()
  {
    String label = name == null ? "" : name.trim().toLowerCase(Locale.ROOT)
        .replaceAll("[^a-z0-9._-]+", "-")
        .replaceAll("(^-+|-+$)", "");
    if (label.isEmpty())
      label = "private-key";
    return "ironkeys-" + label + "-" + keyId + ".ikb";
  }
}
