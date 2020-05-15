package com.github.jaskelai.infobez

import java.math.BigInteger
import java.math.BigInteger.*
import java.security.MessageDigest
import java.util.*

fun main() {
    val message = "hi mom"
    val rsa = RSA(1024)
    var result = forgeSignature(message.toByteArray(), RSA(1024))

    println(isValidSignature(message.toByteArray(), result, rsa))
}

fun forgeSignature(message: ByteArray, rsa: RSA): ByteArray {

    // 00h 01h ffh ffh ... ffh ffh 00h + HASH
    val paddedHash = byteArrayOf(0, 1, 0xff.toByte(), 0) + getSHA1Hash(message)

    // находим минимальное значение для промежутка
    val paddedMessageMinimum = ByteArray(getRsaBlockLength(rsa) - paddedHash.size)
    val newMinimumPaddedMessage = paddedHash + paddedMessageMinimum

    // находим максимальное значение для промежутка
    val paddedMessageMaximum = ByteArray(getRsaBlockLength(rsa) - paddedHash.size) { -1 }
    val newMaximumPaddedMessgae = paddedHash + paddedMessageMaximum

    // находим корень из куба для числа в промежутке 00h 01h ... ffh 00h ASN.1.
    return cubeRootBetween(BigInteger(newMinimumPaddedMessage), BigInteger(newMaximumPaddedMessgae)).toByteArray()
}

// квадратый корень из куба в промежутке из значений
private fun cubeRootBetween(minimum: BigInteger, maximum: BigInteger): BigInteger {

    var min = TWO
    var max = minimum

    var result = ZERO

    while ((minimum < result.pow(3) && (result.pow(3) < maximum)).not()) {

        if (result.pow(3) < minimum) min = result else max = result

        result = min.add(max.add(result.negate()).divide(TWO))
    }
    return result
}

// Получаем необходимый размер RSA-блока
private fun getRsaBlockLength(publicKey: RSA): Int = with(publicKey.publicKey.second.toByteArray()) {
        size - size % 8
    }

private fun getSHA1Hash(input: ByteArray): ByteArray = MessageDigest.getInstance("SHA-1").digest(input)

// Проверяем валидность полученного резльтата
fun isValidSignature(signedMessage: ByteArray, signature: ByteArray, rsa: RSA): Boolean {

    val hash = getSHA1Hash(signedMessage)

    val decrypt = rsa.encrypt(BigInteger(signature)).toByteArray()

    val hashStart: Int = findPaddingEnd(decrypt) + 1

    val signedHash = Arrays.copyOfRange(decrypt, hashStart, hashStart + hash.size)

    return hash.contentEquals(signedHash)
}

// Находим окончание полученного сдвига
private fun findPaddingEnd(input: ByteArray): Int {
    for (i in 2 until input.size) {
        if (input[i] == 0.toByte()) return i
    }
    return 0
}
