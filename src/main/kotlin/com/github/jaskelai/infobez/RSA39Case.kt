package com.github.jaskelai.infobez

import java.math.BigInteger
import java.security.SecureRandom

@ExperimentalStdlibApi
fun main() {
    val testString = "Oh, wow, it works"
    val testBigInteger = BigInteger(testString.toByteArray())
    val rsa = RSA(512)
    val encrypted = rsa.encrypt(testBigInteger)
    val decrypted = rsa.decrypt(encrypted)
    println(decrypted.toByteArray().decodeToString() == testString)
}

class RSA(private val size: Int) {

    private val random = SecureRandom()
    private var p = BigInteger.ZERO
    private var q = BigInteger.ZERO
    private var n = BigInteger.ZERO
    private var t = BigInteger.ZERO
    private val e = BigInteger.valueOf(3)
    private var d: BigInteger = BigInteger.ZERO

    val publicKey: Pair<BigInteger, BigInteger>

    init {
        var notCompatable = true

        while (notCompatable) {
            notCompatable = false
            try {
                generateKeys()
            } catch (ex: ArithmeticException) {
                notCompatable = true
            }
        }
        publicKey = Pair(e, n)
    }

    @Throws(ArithmeticException::class)
    private fun generateKeys() {
        p = BigInteger.probablePrime(size / 2, random)
        q = BigInteger.probablePrime(size / 2, random)
        n = p * q
        t = lcm(p - BigInteger.ONE, q - BigInteger.ONE)
        d = e.modInverse(t)
    }

    // Шифрование
    fun encrypt(base: BigInteger): BigInteger = base.modPow(e, n)

    // Дешифрование
    fun decrypt(base: BigInteger): BigInteger = base.modPow(d, n)

    // Наибольший общий делитель
    private fun gcd(a: BigInteger, b: BigInteger): BigInteger = a.gcd(b)

    // Наименьшее общее кратное
    private fun lcm(a: BigInteger, b: BigInteger): BigInteger {
        val gcd = gcd(a, b)
        val abs = (a * b).abs()
        return abs / gcd
    }
}