package juloo.keyboard2.ironkeys;

import org.junit.Test;
import static org.junit.Assert.*;

public class IronKeysPublicKeyShareCodecTest
{
  private final IronKeysPrivateKeyGenerator _generator =
      new IronKeysPrivateKeyGenerator();
  private final IronKeysPublicKeyShareCodec _codec =
      new IronKeysPublicKeyShareCodec();

  @Test
  public void public_key_share_round_trip() throws Exception
  {
    IronKeysPrivateKey privateKey = _generator.generate("Alice");

    IronKeysPublicKeyShareCodec.DecodeResult decoded =
        _codec.decode(_codec.encode(privateKey));

    assertEquals(IronKeysPublicKeyShareCodec.DecodeResult.Status.SUCCESS,
        decoded.status);
    assertEquals(privateKey.name, decoded.publicKey.name);
    assertEquals(privateKey.keyId, decoded.publicKey.keyId);
    assertEquals(privateKey.algorithm, decoded.publicKey.algorithm);
    assertEquals(privateKey.ecPublicKeyBase64,
        decoded.publicKey.ecPublicKeyBase64);
    assertEquals(privateKey.mlKemPublicKeyBase64,
        decoded.publicKey.mlKemPublicKeyBase64);
    assertEquals(privateKey.fingerprint, decoded.publicKey.fingerprint);
  }

  @Test
  public void public_key_share_never_contains_private_material()
      throws Exception
  {
    IronKeysPrivateKey privateKey = _generator.generate("Private");

    String share = _codec.encode(privateKey);

    assertFalse(share.contains(privateKey.ecPrivateKeyBase64));
    assertFalse(share.contains(privateKey.mlKemPrivateKeyBase64));
  }

  @Test
  public void public_key_share_rejects_tampered_fingerprint()
      throws Exception
  {
    IronKeysPrivateKey privateKey = _generator.generate("Broken");

    IronKeysPublicKeyShareCodec.DecodeResult decoded = _codec.decode(
        _codec.encode(privateKey).replace(privateKey.fingerprint,
            "0000 1111"));

    assertEquals(IronKeysPublicKeyShareCodec.DecodeResult.Status.INVALID,
        decoded.status);
  }

  @Test
  public void public_key_share_reports_unsupported_algorithm()
      throws Exception
  {
    IronKeysPrivateKey privateKey = _generator.generate("Unsupported");

    IronKeysPublicKeyShareCodec.DecodeResult decoded = _codec.decode(
        _codec.encode(privateKey).replace(privateKey.algorithm,
            "UNKNOWN_SUITE"));

    assertEquals(
        IronKeysPublicKeyShareCodec.DecodeResult.Status.UNSUPPORTED_ALGORITHM,
        decoded.status);
  }

  @Test
  public void public_key_share_reports_legacy_version() throws Exception
  {
    IronKeysPrivateKey privateKey = _generator.generate("Legacy");

    IronKeysPublicKeyShareCodec.DecodeResult decoded = _codec.decode(
        _codec.encode(privateKey).replace("version: 2", "version: 1"));

    assertEquals(
        IronKeysPublicKeyShareCodec.DecodeResult.Status.LEGACY_UNSUPPORTED,
        decoded.status);
  }

  @Test
  public void public_key_share_rejects_malformed_text()
  {
    IronKeysPublicKeyShareCodec.DecodeResult decoded =
        _codec.decode("not an ironkeys public key");

    assertEquals(IronKeysPublicKeyShareCodec.DecodeResult.Status.INVALID,
        decoded.status);
  }
}
