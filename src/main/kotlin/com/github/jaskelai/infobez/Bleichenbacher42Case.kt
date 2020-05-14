package com.github.jaskelai.infobez

import java.math.BigInteger
import java.math.BigInteger.TWO
import java.math.BigInteger.valueOf
import java.security.MessageDigest
import java.util.*

fun main() {
    val message = "hi mom"
    val rsa = RSA(1024)
    var result = forgeSignature(message.toByteArray(), RSA(1024))

    println(isValidSignature(message.toByteArray(), result, rsa))
}

fun forgeSignature(message: ByteArray, rsa: RSA): ByteArray {

    val asn = byteArrayOf(30, 21, 30, 9, 6, 5, 43, 14, 3, 2, 26, 5, 0, 4, 14)

    // 00h 01h ffh ffh ... ffh ffh 00h + ASN + HASH
    val paddedHash = byteArrayOf(0, 1, 0xff.toByte(), 0) + asn + getSHA1Hash(message)

    // находим минимальное значение для промежутка
    val paddedMessageMinimum = ByteArray(getRsaBlockLength(rsa))
    val newMinimumPaddedMessage = paddedHash + paddedMessageMinimum

    // находим максимальное значение для промежутка
    val paddedMessageMaximum = ByteArray(getRsaBlockLength(rsa)) { -1 }
    val newMaximumPaddedMessgae = paddedHash + paddedMessageMaximum

    // находим корень из куба для числа в промежутке 00h 01h ... ffh 00h ASN.1.
    return cubeRootBetween(BigInteger(newMinimumPaddedMessage), BigInteger(newMaximumPaddedMessgae)).toByteArray()
}

// квадратый корень из куба в промежутке
private fun cubeRootBetween(minimum: BigInteger, maximum: BigInteger): BigInteger {
    var min = TWO
    var max = minimum
    var current = min.divide(valueOf(3))
    while (!(minimum < current.pow(3) && (current.pow(3) < maximum))) {
        if (current.pow(3) < minimum) {
            min = current
            current = min.add(max.add(current.negate()).divide(TWO))
        } else {
            max = current
            current = min.add(max.add(current.negate()).divide(TWO))
        }
    }
    return current
}

private fun getRsaBlockLength(publicKey: RSA): Int = with(publicKey.publicKey.second.toByteArray()) {
        size - size % 8 - 1
    }

private fun getSHA1Hash(input: ByteArray): ByteArray = MessageDigest.getInstance("SHA-1").digest(input)

// Проверяем валидность
fun isValidSignature(signedMessage: ByteArray, signature: ByteArray, rsa: RSA): Boolean {
    val hash = getSHA1Hash(signedMessage)
    val decrypt = rsa.encrypt(BigInteger(signature)).toByteArray()
    val hashStart: Int = findPaddingEnd(decrypt) + 1
    val signedHash = Arrays.copyOfRange(decrypt, hashStart, hashStart + hash.size)
    return hash.contentEquals(signedHash).not()
}

private fun findPaddingEnd(decrypt: ByteArray): Int {
    for (indx in 2 until decrypt.size) {
        if (decrypt[indx] == 0.toByte()) return indx
    }
    return 0
}
