package juloo.keyboard2.ironkeys;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;

public final class IronKeysMessageCipher
{
  public static final int MAX_PLAINTEXT_CHARS = 32;
  public static final int MAX_RECIPIENTS = 1;

  private static final String EC_ALGORITHM = "EC";
  private static final String ECDH_ALGORITHM = "ECDH";
  private static final String AES_ALGORITHM = "AES";
  private static final String AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding";
  private static final String HMAC_SHA256 = "HmacSHA256";
  private static final int AES_KEY_BYTES = 32;
  private static final int GCM_NONCE_BYTES = 12;
  private static final int GCM_TAG_BITS = 128;
  private static final byte[] HKDF_SALT =
      "IronKeys message v1".getBytes(StandardCharsets.UTF_8);
  private static final byte[] MESSAGE_AAD_PREFIX =
      "IronKeys message payload v1".getBytes(StandardCharsets.UTF_8);
  private static final byte[] WRAP_AAD_PREFIX =
      "IronKeys message key wrap v1".getBytes(StandardCharsets.UTF_8);

  private final SecureRandom _secureRandom;
  private final IronKeysMessageCodec _codec;

  public IronKeysMessageCipher()
  {
    _secureRandom = new SecureRandom();
    _codec = new IronKeysMessageCodec();
  }

  public String encrypt(String plaintext, IronKeysPrivateKey senderPrivateKey,
      List<IronKeysPublicKey> recipientPublicKeys)
      throws GeneralSecurityException
  {
    if (senderPrivateKey == null)
      throw new GeneralSecurityException("Select an IronKeys private key.");
    if (recipientPublicKeys == null || recipientPublicKeys.isEmpty())
      throw new GeneralSecurityException("Select at least one recipient.");
    String normalizedPlaintext = plaintext == null ? "" : plaintext;
    if (normalizedPlaintext.length() > MAX_PLAINTEXT_CHARS)
      throw new GeneralSecurityException(
          "Messages are limited to 32 characters.");

    List<IronKeysPublicKey> recipients =
        deduplicatedRecipients(recipientPublicKeys);
    if (recipients.size() != MAX_RECIPIENTS)
      throw new GeneralSecurityException("Select exactly one recipient.");
    byte[] messageKey = randomBytes(AES_KEY_BYTES);
    byte[] messageNonce = randomBytes(GCM_NONCE_BYTES);
    byte[] plaintextBytes = normalizedPlaintext.getBytes(StandardCharsets.UTF_8);
    byte[] messageCiphertext = aesGcmEncrypt(messageKey, messageNonce,
        messageAad(senderPrivateKey.keyId), plaintextBytes);

    List<IronKeysMessageCodec.RecipientEnvelope> envelopes =
        new ArrayList<IronKeysMessageCodec.RecipientEnvelope>();
    for (IronKeysPublicKey recipient : recipients)
      envelopes.add(encryptEnvelope(senderPrivateKey, recipient, messageKey));

    return _codec.encode(new IronKeysMessageCodec.IronKeysMessage(
        senderPrivateKey.keyId,
        senderPrivateKey.fingerprint,
        senderPrivateKey.ecPublicKeyBase64,
        senderPrivateKey.mlKemPublicKeyBase64,
        messageNonce,
        messageCiphertext,
        envelopes));
  }

  public String decrypt(String encodedMessage,
      IronKeysPrivateKey recipientPrivateKey)
      throws GeneralSecurityException
  {
    if (recipientPrivateKey == null)
      throw new GeneralSecurityException("Select an IronKeys private key.");

    IronKeysMessageCodec.DecodeResult decodeResult =
        _codec.decode(encodedMessage);
    if (decodeResult.status !=
        IronKeysMessageCodec.DecodeResult.Status.SUCCESS)
      throw new GeneralSecurityException("Invalid IronKeys message.");

    IronKeysMessageCodec.IronKeysMessage message = decodeResult.message;
    IronKeysMessageCodec.RecipientEnvelope envelope =
        findEnvelope(message, recipientPrivateKey.keyId);
    if (envelope == null)
      throw new GeneralSecurityException(
          "This IronKeys private key cannot decrypt the message.");

    byte[] messageKey = decryptEnvelope(message, recipientPrivateKey,
        envelope);
    byte[] plaintext = aesGcmDecrypt(messageKey, message.messageNonce,
        messageAad(message.senderKeyId), message.messageCiphertext);
    return new String(plaintext, StandardCharsets.UTF_8);
  }

  public List<IronKeysPublicKey> deduplicatedRecipients(
      List<IronKeysPublicKey> recipientPublicKeys)
  {
    List<IronKeysPublicKey> recipients = new ArrayList<IronKeysPublicKey>();
    Set<String> seenKeyIds = new LinkedHashSet<String>();
    for (IronKeysPublicKey recipient : recipientPublicKeys)
    {
      if (recipient == null || seenKeyIds.contains(recipient.keyId))
        continue;
      recipients.add(recipient);
      seenKeyIds.add(recipient.keyId);
    }
    return recipients;
  }

  private IronKeysMessageCodec.RecipientEnvelope encryptEnvelope(
      IronKeysPrivateKey senderPrivateKey, IronKeysPublicKey recipient,
      byte[] messageKey) throws GeneralSecurityException
  {
    byte[] ecdhSecret = deriveEcdhSecret(
        decodeEcPrivateKey(senderPrivateKey.ecPrivateKeyBase64),
        decodeEcPublicKey(recipient.ecPublicKeyBase64));

    SecretWithEncapsulation mlKemSecret =
        encapsulateMlKem(recipient.mlKemPublicKeyBase64);
    byte[] kek = deriveWrapKey(senderPrivateKey.keyId, recipient.keyId,
        ecdhSecret, mlKemSecret.getSecret());
    byte[] wrapNonce = randomBytes(GCM_NONCE_BYTES);
    byte[] wrappedMessageKey = aesGcmEncrypt(kek, wrapNonce,
        wrapAad(senderPrivateKey.keyId, recipient.keyId), messageKey);
    return new IronKeysMessageCodec.RecipientEnvelope(recipient.keyId,
        mlKemSecret.getEncapsulation(), wrapNonce, wrappedMessageKey);
  }

  private byte[] decryptEnvelope(IronKeysMessageCodec.IronKeysMessage message,
      IronKeysPrivateKey recipientPrivateKey,
      IronKeysMessageCodec.RecipientEnvelope envelope)
      throws GeneralSecurityException
  {
    byte[] ecdhSecret = deriveEcdhSecret(
        decodeEcPrivateKey(recipientPrivateKey.ecPrivateKeyBase64),
        decodeEcPublicKey(message.senderEcPublicKeyBase64));
    byte[] mlKemSecret = extractMlKemSecret(
        recipientPrivateKey.mlKemPrivateKeyBase64,
        envelope.mlKemEncapsulation);
    byte[] kek = deriveWrapKey(message.senderKeyId,
        recipientPrivateKey.keyId, ecdhSecret, mlKemSecret);
    return aesGcmDecrypt(kek, envelope.wrapNonce,
        wrapAad(message.senderKeyId, recipientPrivateKey.keyId),
        envelope.wrappedMessageKey);
  }

  private static IronKeysMessageCodec.RecipientEnvelope findEnvelope(
      IronKeysMessageCodec.IronKeysMessage message, String recipientKeyId)
  {
    for (IronKeysMessageCodec.RecipientEnvelope envelope :
        message.recipients)
      if (envelope.recipientKeyId.equals(recipientKeyId))
        return envelope;
    return null;
  }

  private SecretWithEncapsulation encapsulateMlKem(String publicKeyBase64)
      throws GeneralSecurityException
  {
    try
    {
      AsymmetricKeyParameter publicKey = PublicKeyFactory.createKey(
          IronKeysBase64.decode(publicKeyBase64));
      return new MLKEMGenerator(_secureRandom)
          .generateEncapsulated(publicKey);
    }
    catch (Exception e)
    {
      throw new GeneralSecurityException("Unable to encapsulate ML-KEM key.", e);
    }
  }

  private byte[] extractMlKemSecret(String privateKeyBase64,
      byte[] encapsulation) throws GeneralSecurityException
  {
    try
    {
      AsymmetricKeyParameter privateKey = PrivateKeyFactory.createKey(
          IronKeysBase64.decode(privateKeyBase64));
      return new MLKEMExtractor((MLKEMPrivateKeyParameters)privateKey)
          .extractSecret(encapsulation);
    }
    catch (Exception e)
    {
      throw new GeneralSecurityException("Unable to extract ML-KEM key.", e);
    }
  }

  private static byte[] deriveEcdhSecret(PrivateKey privateKey,
      PublicKey publicKey) throws GeneralSecurityException
  {
    KeyAgreement keyAgreement = KeyAgreement.getInstance(ECDH_ALGORITHM);
    keyAgreement.init(privateKey);
    keyAgreement.doPhase(publicKey, true);
    return keyAgreement.generateSecret();
  }

  private static byte[] deriveWrapKey(String senderKeyId, String recipientKeyId,
      byte[] ecdhSecret, byte[] mlKemSecret) throws GeneralSecurityException
  {
    ByteArrayOutputStream input = new ByteArrayOutputStream();
    writeLengthPrefixed(input, ecdhSecret);
    writeLengthPrefixed(input, mlKemSecret);
    return hkdf(input.toByteArray(), HKDF_SALT,
        wrapAad(senderKeyId, recipientKeyId), AES_KEY_BYTES);
  }

  private static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int size)
      throws GeneralSecurityException
  {
    Mac mac = Mac.getInstance(HMAC_SHA256);
    mac.init(new SecretKeySpec(salt, HMAC_SHA256));
    byte[] prk = mac.doFinal(ikm);
    byte[] result = new byte[size];
    byte[] previous = new byte[0];
    int offset = 0;
    int counter = 1;
    while (offset < size)
    {
      mac.init(new SecretKeySpec(prk, HMAC_SHA256));
      mac.update(previous);
      mac.update(info);
      mac.update((byte)counter);
      previous = mac.doFinal();
      int copyLength = Math.min(previous.length, size - offset);
      System.arraycopy(previous, 0, result, offset, copyLength);
      offset += copyLength;
      counter++;
    }
    return result;
  }

  private static byte[] aesGcmEncrypt(byte[] key, byte[] nonce, byte[] aad,
      byte[] plaintext) throws GeneralSecurityException
  {
    Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, AES_ALGORITHM),
        new GCMParameterSpec(GCM_TAG_BITS, nonce));
    cipher.updateAAD(aad);
    return cipher.doFinal(plaintext);
  }

  private static byte[] aesGcmDecrypt(byte[] key, byte[] nonce, byte[] aad,
      byte[] ciphertext) throws GeneralSecurityException
  {
    Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, AES_ALGORITHM),
        new GCMParameterSpec(GCM_TAG_BITS, nonce));
    cipher.updateAAD(aad);
    return cipher.doFinal(ciphertext);
  }

  private PrivateKey decodeEcPrivateKey(String encodedKeyBase64)
      throws GeneralSecurityException
  {
    return KeyFactory.getInstance(EC_ALGORITHM)
        .generatePrivate(new PKCS8EncodedKeySpec(
            IronKeysBase64.decode(encodedKeyBase64)));
  }

  private PublicKey decodeEcPublicKey(String encodedKeyBase64)
      throws GeneralSecurityException
  {
    return KeyFactory.getInstance(EC_ALGORITHM)
        .generatePublic(new X509EncodedKeySpec(
            IronKeysBase64.decode(encodedKeyBase64)));
  }

  private byte[] randomBytes(int size)
  {
    byte[] value = new byte[size];
    _secureRandom.nextBytes(value);
    return value;
  }

  private static byte[] messageAad(String senderKeyId)
  {
    return asciiJoin(MESSAGE_AAD_PREFIX, senderKeyId);
  }

  private static byte[] wrapAad(String senderKeyId, String recipientKeyId)
  {
    return asciiJoin(WRAP_AAD_PREFIX, senderKeyId, recipientKeyId);
  }

  private static byte[] asciiJoin(byte[] prefix, String... values)
  {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    output.write(prefix, 0, prefix.length);
    for (String value : values)
    {
      output.write(0);
      byte[] valueBytes = value.getBytes(StandardCharsets.UTF_8);
      output.write(valueBytes, 0, valueBytes.length);
    }
    return output.toByteArray();
  }

  private static void writeLengthPrefixed(ByteArrayOutputStream output,
      byte[] value)
  {
    int length = value.length;
    output.write((length >>> 24) & 0xff);
    output.write((length >>> 16) & 0xff);
    output.write((length >>> 8) & 0xff);
    output.write(length & 0xff);
    output.write(value, 0, value.length);
  }
}
