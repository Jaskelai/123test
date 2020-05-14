package com.github.jaskelai.infobez

import java.math.BigDecimal
import java.math.BigInteger
import java.util.*

fun main() {

    val msg =
        Base64.getDecoder().decode("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")

    val rsa = RSA(1024)
    val encryptedMsg = rsa.encrypt(BigInteger(msg))

   parityOracleAttack(encryptedMsg, rsa, true)
}

fun parityOracleAttack(cipherText: BigInteger, rsa: RSA, wantToPrint: Boolean): BigInteger {
    val n: BigInteger = rsa.publicKey.second
    var cipher = cipherText
    var minimum = BigDecimal.ZERO
    var maximum = BigDecimal(n) //n.add(BigInteger.ONE.negate());
    val encryptedMultiplier: BigInteger = rsa.encrypt(BigInteger.TWO)
    while (BigDecimal.valueOf(0.5) < maximum.add(minimum.negate())) {
        cipher = cipher.multiply(encryptedMultiplier).mod(n)
        val half = minimum.add(maximum).divide(BigDecimal.valueOf(2))
        val even: Boolean = rsa.isEven(cipher)
        if (even) {
            maximum = half
        } else {
            minimum = half
        }
        if (wantToPrint) {
            println(maximum)
            println(String(maximum.toBigInteger().toByteArray()))
        }
    }
    return maximum.toBigInteger()
}

private fun ByteArray.toBigInteger() = BigInteger(this)

private fun RSA.isEven(encryptedData: BigInteger): Boolean =
    encryptedData.modPow(publicKey.first, publicKey.second).mod(BigInteger.TWO) == BigInteger.ZERO
