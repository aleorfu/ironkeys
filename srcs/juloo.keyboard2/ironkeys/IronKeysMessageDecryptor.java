package juloo.keyboard2.ironkeys;

import java.security.GeneralSecurityException;
import java.util.List;

public final class IronKeysMessageDecryptor
{
  private final IronKeysMessageCodec _codec;
  private final IronKeysMessageCipher _cipher;

  public IronKeysMessageDecryptor()
  {
    _codec = new IronKeysMessageCodec();
    _cipher = new IronKeysMessageCipher();
  }

  public Result decryptWithAnyPrivateKey(String encodedMessage,
      List<IronKeysPrivateKey> privateKeys)
  {
    IronKeysMessageCodec.DecodeResult decoded = _codec.decode(encodedMessage);
    if (decoded.status != IronKeysMessageCodec.DecodeResult.Status.SUCCESS)
      return Result.failure(Status.INVALID_MESSAGE, null);
    if (privateKeys == null || privateKeys.isEmpty())
      return Result.failure(Status.NO_PRIVATE_KEYS, null);

    boolean matchingKeyFailed = false;
    GeneralSecurityException lastException = null;
    for (IronKeysMessageCodec.RecipientEnvelope envelope :
        decoded.message.recipients)
    {
      for (IronKeysPrivateKey privateKey : privateKeys)
      {
        if (privateKey == null ||
            !envelope.recipientKeyId.equals(privateKey.keyId))
          continue;
        try
        {
          return Result.success(_cipher.decrypt(encodedMessage, privateKey));
        }
        catch (GeneralSecurityException e)
        {
          matchingKeyFailed = true;
          lastException = e;
        }
      }
    }
    return matchingKeyFailed
        ? Result.failure(Status.DECRYPTION_FAILED, lastException)
        : Result.failure(Status.NO_MATCHING_PRIVATE_KEY, null);
  }

  public static enum Status
  {
    SUCCESS,
    INVALID_MESSAGE,
    NO_PRIVATE_KEYS,
    NO_MATCHING_PRIVATE_KEY,
    DECRYPTION_FAILED,
  }

  public static final class Result
  {
    public final Status status;
    public final String plaintext;
    public final GeneralSecurityException exception;

    private Result(Status status, String plaintext,
        GeneralSecurityException exception)
    {
      this.status = status;
      this.plaintext = plaintext;
      this.exception = exception;
    }

    static Result success(String plaintext)
    {
      return new Result(Status.SUCCESS, plaintext, null);
    }

    static Result failure(Status status, GeneralSecurityException exception)
    {
      return new Result(status, null, exception);
    }
  }
}
