package com.github.jaskelai.infobez

import java.math.BigDecimal
import java.math.BigInteger
import java.math.BigInteger.TWO
import java.util.*

fun main() {

    val msg = Base64.getDecoder()
        .decode("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")

    val rsa = RSA(1024)
    val encryptedMsg = rsa.encrypt(BigInteger(msg))

    println(attack(encryptedMsg, rsa).toByteArray().contentToString())
}

fun attack(cipherText: BigInteger, rsa: RSA): BigInteger {

    val n: BigInteger = rsa.publicKey.second
    var cipher = cipherText

    var minDecimal = BigDecimal.ZERO
    var maxDecimal = BigDecimal(n)

    val encryptedMultiplier = rsa.encrypt(TWO)

    // Проверяем каждый бит сообщения
    while (BigDecimal.valueOf(0.5) < maxDecimal.add(minDecimal.negate())) {

        cipher = cipher.multiply(encryptedMultiplier).mod(n)

        // удваиваем шифртекст
        val half = (minDecimal + maxDecimal) / BigDecimal.valueOf(2)

        // Проверяем четность после удвоения
        val even = rsa.isEven(cipher)

        if (even) { maxDecimal = half } else { minDecimal = half }
    }

    return maxDecimal.toBigInteger()
}


// Проверка на четность
private fun RSA.isEven(encryptedData: BigInteger): Boolean {
    return encryptedData.modPow(publicKey.first, publicKey.second).mod(TWO) == BigInteger.ZERO
}
