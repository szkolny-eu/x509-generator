/*
 * Copyright (c) Kuba Szczodrzyński 2020-10-26.
 */

package eu.szkolny.x509

import eu.szkolny.x509.X509Generator.Algorithm.*
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.ByteArrayInputStream
import java.security.KeyPairGenerator
import java.security.cert.CertificateFactory

class GeneratorTest {
    private val algorithms = mapOf(
        ("RSA" to 2048) to listOf(RSA_MD2, RSA_MD5, RSA_SHA1, RSA_SHA224, RSA_SHA256, RSA_SHA384, RSA_SHA512),
        ("DSA" to 1024) to listOf(DSA_SHA1, DSA_SHA224, DSA_SHA256),
        ("EC" to 256) to listOf(ECDSA_SHA1, ECDSA_SHA224, ECDSA_SHA256, ECDSA_SHA384, ECDSA_SHA512)
    )

    @Test
    fun generatorTest() {
        val certificateFactory = CertificateFactory.getInstance("X.509")

        algorithms.forEach { (keyAlg, hashList) ->
            val keyPairGenerator = KeyPairGenerator.getInstance(keyAlg.first)
            keyPairGenerator.initialize(keyAlg.second)
            val keyPair = keyPairGenerator.generateKeyPair()

            hashList.forEach { hashAlgorithm ->
                val cert = X509Generator(hashAlgorithm)
                    .generate(subject = mapOf("CN" to "GeneratorTest"), serialNumber = 1, keyPair = keyPair)

                val x509 = certificateFactory.generateCertificate(ByteArrayInputStream(cert))
                x509.verify(keyPair.public)

                assertEquals(x509.publicKey, keyPair.public)
            }
        }
    }
}
