# x509-generator

A hacky solution to the difficulties of generating an X.509 certificate in JVM/Android.

## Usage

```groovy
repositories {
    jcenter()
}

dependencies {
    implementation 'eu.szkolny:x509-generator:1.0.0'
}
```

```kotlin
val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
keyPairGenerator.initialize(2048)
val keyPair = keyPairGenerator.generateKeyPair()

val notBefore = ZonedDateTime.now()
val notAfter = notBefore.plusYears(10)

val cert = X509Generator(X509Generator.Algorithm.RSA_SHA256)
    .generate(
        subject = mapOf(
            "CN" to "Certificate Example",
            "O" to "IT"
        ),
        issuer = mapOf("CN" to "Certificate Issuer"),
        notBefore = notBefore,
        notAfter = notAfter,
        serialNumber = 1337,
        keyPair = keyPair
    )
```

[Available signature algorithms](https://github.com/szkolny-eu/x509-generator/blob/master/src/main/kotlin/eu/szkolny/x509/X509Generator.kt#L27) - X509Generator.kt#27

[Available subject claims](https://github.com/szkolny-eu/x509-generator/blob/master/src/main/kotlin/eu/szkolny/x509/X509Generator.kt#L15) - X509Generator.kt#15
