package com.github.jaskelai.infobez

import java.math.BigInteger


fun main() {
    val text = "HMMMMMM"
    val rsaAttackResult = attack(text, 1024)
    println(rsaAttackResult == BigInteger(text.toByteArray()))
}

fun attack(input: String, size: Int): BigInteger {

    val rsa0 = RSA(size)
    val c0 = rsa0.encrypt(BigInteger(input.toByteArray()))
    val n0 = rsa0.publicKey.second

    val rsa1 = RSA(size)
    val c1 = rsa1.encrypt(BigInteger(input.toByteArray()))
    val n1 = rsa1.publicKey.second

    val rsa2 = RSA(size)
    val c2 = rsa2.encrypt(BigInteger(input.toByteArray()))
    val n2 = rsa2.publicKey.second

    val m0 = n1 * n2
    val m1 = n0 * n2
    val m2 = n0 * n1


    val temp0 = c0 * m0 * m0.modInverse(n0)
    val temp1 = c1 * m1 * m1.modInverse(n1)
    val temp2 = c2 * m2 * m2.modInverse(n2)

    return cubeRoot((temp0 + temp1 + temp2) % (n0 * n1 * n2))
}
