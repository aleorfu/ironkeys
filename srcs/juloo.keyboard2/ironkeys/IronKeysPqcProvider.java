package juloo.keyboard2.ironkeys;

import java.security.Provider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

final class IronKeysPqcProvider
{
  private static Provider _provider;

  private IronKeysPqcProvider() {}

  static synchronized Provider provider()
  {
    if (_provider == null)
      _provider = new BouncyCastleProvider();
    return _provider;
  }
}
