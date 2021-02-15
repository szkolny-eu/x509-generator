/*
 * Copyright (c) Kuba Szczodrzyński 2020-10-26.
 */

package eu.szkolny.x509

import java.security.KeyPair
import java.security.Signature
import java.time.ZonedDateTime
import java.security.MessageDigest.getInstance as createSign

class X509Generator(
    val signatureAlgorithm: Algorithm
) {
    private val rdnTable = mapOf(
        "CN" to "2.5.4.3",
        "OU" to "2.5.4.11",
        "O" to "2.5.4.10",
        "L" to "2.5.4.7",
        "ST" to "2.5.4.8",
        "C" to "2.5.4.6",
        "SN" to "2.5.4.5",
        "GN" to "2.5.4.42",
        "SURNAME" to "2.5.4.4"
    )

    enum class Algorithm(val oid: String, val hashAlg: String) {
        RSA_MD2("1.2.840.113549.1.1.2", "MD2withRSA"),
        RSA_MD5("1.2.840.113549.1.1.4", "MD5withRSA"),
        RSA_SHA1("1.2.840.113549.1.1.5", "SHA1withRSA"),
        RSA_SHA224("1.2.840.113549.1.1.14", "SHA224withRSA"),
        RSA_SHA256("1.2.840.113549.1.1.11", "SHA256withRSA"),
        RSA_SHA384("1.2.840.113549.1.1.12", "SHA384withRSA"),
        RSA_SHA512("1.2.840.113549.1.1.13", "SHA512withRSA"),
        DSA_SHA1("1.2.840.10040.4.3", "SHA1withDSA"),
        DSA_SHA224("2.16.840.1.101.3.4.3.1", "SHA224withDSA"),
        DSA_SHA256("2.16.840.1.101.3.4.3.2", "SHA256withDSA"),
        ECDSA_SHA1("1.2.840.10045.4.1", "SHA1withECDSA"),
        ECDSA_SHA224("1.2.840.10045.4.3.1", "SHA224withECDSA"),
        ECDSA_SHA256("1.2.840.10045.4.3.2", "SHA256withECDSA"),
        ECDSA_SHA384("1.2.840.10045.4.3.3", "SHA384withECDSA"),
        ECDSA_SHA512("1.2.840.10045.4.3.4", "SHA512withECDSA")
    }

    private fun buildName(name: Map<String, String>): ASN1Structure {
        val structure = ASN1Structure() /* Name */
        name.forEach { (key, value) ->
            val oid = rdnTable[key] ?: throw IllegalArgumentException()

            structure.appendSet(
                ASN1Structure().appendSequence( /* RDNSequence */
                    ASN1Structure() /* RelativeDistinguishedName AttributeTypeAndValue */
                        .appendObjectId(oid)
                        .appendString(value, utf8 = true)
                )
            )
        }
        return structure
    }

    fun generate(
        subject: Map<String, String>,
        issuer: Map<String, String> = subject,
        notBefore: ZonedDateTime = ZonedDateTime.now(),
        notAfter: ZonedDateTime = notBefore.plusYears(20),
        serialNumber: Long = System.currentTimeMillis(),
        keyPair: KeyPair
    ): ByteArray {
        val publicKey = keyPair.public
        val privateKey = keyPair.private

        val algorithmIdentifier = ASN1Structure() /* AlgorithmIdentifier */
            .appendObjectId(signatureAlgorithm.oid) /* algorithm OBJECT IDENTIFIER */
            .appendNull() /* parameters ANY DEFINED BY algorithm OPTIONAL */

        val validity = ASN1Structure() /* Validity */
            .appendUTCTime(notBefore) /* notBefore Time */
            .appendUTCTime(notAfter) /* notAfter Time */

        val subjectName = buildName(subject)
        val issuerName = buildName(issuer)

        val tbsCertificate = ASN1Structure() /* TBSCertificate */
            .appendExplicit(0,
                ASN1Structure() /* version EXPLICIT Version DEFAULT v1 */
                    .appendInteger(2) /* INTEGER v3(2) */
            )
            .appendLong(serialNumber) /* serialNumber CertificateSerialNumber */
            .appendSequence(algorithmIdentifier) /* signature AlgorithmIdentifier */
            .appendSequence(issuerName) /* issuer Name */
            .appendSequence(validity) /* validity Validity */
            .appendSequence(subjectName) /* subject Name */
            .appendRaw(publicKey.encoded) /* subjectPublicKeyInfo SubjectPublicKeyInfo */

        val tbsBytes = tbsCertificate.getBytes().toByteArray()

        val signature = Signature.getInstance(signatureAlgorithm.hashAlg)
        signature.initSign(privateKey)
        signature.update(tbsBytes)

        return ASN1Structure()
            .appendRaw(tbsBytes) /* tbsCertificate TBSCertificate */
            .appendSequence(algorithmIdentifier) /* signatureAlgorithm AlgorithmIdentifier */
            .appendBitString(signature.sign()) /* signatureValue BIT STRING */
            .getBytes()
            .toByteArray()
    }

    fun getFingerprint(bytes: ByteArray) = createSign("SHA-1").digest(bytes)
}
