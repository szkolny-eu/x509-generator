/*
 * Copyright (c) Kuba Szczodrzyński 2020-10-26.
 */

package eu.szkolny.x509

import java.math.BigInteger
import java.time.LocalDateTime

class ASN1Structure {
    private val data = mutableListOf<Byte>()

    private fun appendTag(tag: Int, target: MutableList<Byte> = data) {
        target.add(tag.toByte())
    }

    private fun appendLength(length: Int, target: MutableList<Byte> = data) {
        if (length < 128) {
            target.add(length.toByte())
            return
        }
        val bytes = length
            .toBigInteger()
            .toByteArray()
            .dropWhile { it.compareTo(0) == 0 }
        target.add((bytes.size or 0b10000000).toByte())
        target.addAll(bytes)
    }

    private fun appendTLV(tag: Int, value: List<Byte>, target: MutableList<Byte> = data): ASN1Structure {
        appendTag(tag, target)
        appendLength(value.size, target)
        target.addAll(value)
        return this
    }

    private fun appendTLV(tag: Int, value: ByteArray, target: MutableList<Byte> = data): ASN1Structure {
        appendTag(tag, target)
        appendLength(value.size, target)
        value.forEach { target.add(it) }
        return this
    }

    fun appendInteger(number: Int) = appendBigInteger(number.toBigInteger())

    fun appendLong(number: Long) = appendBigInteger(number.toBigInteger())

    fun appendBigInteger(number: BigInteger): ASN1Structure {
        val bytes = number.toByteArray().dropWhile { it.compareTo(0) == 0 }
        return appendTLV(0x02, bytes)
    }

    fun appendString(string: String, utf8: Boolean = false): ASN1Structure {
        val bytes = string.encodeToByteArray()
        return appendTLV(if (utf8) 0x0c else 0x13, bytes)
    }

    fun appendSequence(structure: ASN1Structure): ASN1Structure {
        return appendTLV(0x30, structure.data)
    }

    fun appendSet(structure: ASN1Structure): ASN1Structure {
        return appendTLV(0x31, structure.data)
    }

    fun appendBitString(bytes: ByteArray): ASN1Structure {
        appendTag(0x03)
        appendLength(bytes.size + 1)
        data.add(0x00)
        bytes.forEach { data.add(it) }
        return this
    }

    fun appendOctetString(bytes: ByteArray): ASN1Structure {
        return appendTLV(0x04, bytes)
    }

    fun appendBoolean(boolean: Boolean): ASN1Structure {
        return appendTLV(0x01, listOf(if (boolean) 0xff.toByte() else 0x00))
    }

    fun appendNull(): ASN1Structure {
        return appendTLV(0x05, emptyList())
    }

    fun appendUTCTime(time: LocalDateTime): ASN1Structure {
        val year = if (time.year >= 2000) time.year - 2000 else time.year - 1900
        val list = listOf(
            year,
            time.monthValue,
            time.dayOfMonth,
            time.hour,
            time.minute,
            time.second
        )
        val bytes = list
            .joinToString("") { it.toString().padStart(2, '0') }
            .plus("Z")
            .encodeToByteArray()
        return appendTLV(0x17, bytes)
    }

    fun appendObjectId(oid: String): ASN1Structure {
        val idList = oid.split(".").map { it.toInt() }
        val bytes = mutableListOf<Byte>()
        idList.subList(2, idList.size).asReversed().forEach {
            var first = true
            var number = it
            while (number > 0) {
                var byte = number and 0b01111111
                number = number shr 7
                if (!first && it > 128)
                    byte = byte or 0b10000000
                first = false
                bytes.add(byte.toByte())
            }
        }
        bytes.add((idList[0] * 40 + idList[1]).toByte())
        return appendTLV(0x06, bytes.asReversed())
    }

    fun appendExplicit(position: Int, structure: ASN1Structure): ASN1Structure {
        return appendTLV(0xa0 or position, structure.data)
    }

    fun appendRaw(bytes: ByteArray): ASN1Structure {
        bytes.forEach { data.add(it) }
        return this
    }

    fun getBytes(): List<Byte> {
        val result = mutableListOf<Byte>()
        appendTLV(0x30, data, result)
        return result
    }
}
