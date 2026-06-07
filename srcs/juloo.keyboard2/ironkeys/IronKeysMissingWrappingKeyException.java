package juloo.keyboard2.ironkeys;

import java.security.GeneralSecurityException;

final class IronKeysMissingWrappingKeyException
    extends GeneralSecurityException
{
  IronKeysMissingWrappingKeyException()
  {
    super("Missing key directory wrapping key.");
  }
}
