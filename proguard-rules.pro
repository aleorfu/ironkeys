-keep public class juloo.cdict.* {
  public protected private *;
}

# Bouncy Castle discovers its JCA algorithm mappings and implementations by
# their fully qualified class names. Keep the ML-KEM classes used by IronKeys;
# otherwise R8 removes them from release builds and the provider cannot create
# an MLKEM KeyPairGenerator/KeyFactory.
-keep class org.bouncycastle.jcajce.provider.asymmetric.MLKEM$Mappings { *; }
-keep class org.bouncycastle.jcajce.provider.asymmetric.mlkem.** { *; }
