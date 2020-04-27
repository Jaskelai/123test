package com.github.jaskelai.infobez

import java.math.BigInteger
import java.security.SecureRandom

@ExperimentalStdlibApi
fun main() {
    val testString = "Oh, wow, it works"
    val testBigInteger = BigInteger(testString.toByteArray())
    val rsa = RSA39Case(512)
    val encrypted = rsa.encrypt(testBigInteger)
    val decrypted = rsa.decrypt(encrypted)
    println(decrypted.toByteArray().decodeToString() == testString)
}

class RSA39Case(private val size: Int) {

    private val random = SecureRandom()
    private var p: BigInteger? = null
    private var q: BigInteger? = null
    private var n: BigInteger? = null
    private var t: BigInteger? = null
    private val e = BigInteger.valueOf(3)
    private var d: BigInteger? = null

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
    }

    @Throws(ArithmeticException::class)
    private fun generateKeys() {
        p = BigInteger.probablePrime(size, random)
        q = BigInteger.probablePrime(size, random)
        n = p?.multiply(q)
        t = lcm(p?.minus(BigInteger.ONE), q?.minus(BigInteger.ONE))
        d = e.modInverse(t)
    }

    // Шифрование
    fun encrypt(base: BigInteger): BigInteger = base.modPow(e, n)

    // Дешифрование
    fun decrypt(base: BigInteger): BigInteger = base.modPow(d, n)

    // Наибольший общий делитель
    private fun gcd(a: BigInteger?, b: BigInteger?): BigInteger? = a?.gcd(b)

    // Наименьшее общее кратное
    private fun lcm(a: BigInteger?, b: BigInteger?): BigInteger? {
        val gcd = gcd(a, b)
        val absProduct = a?.multiply(b)?.abs()
        return absProduct?.divide(gcd)
    }
}