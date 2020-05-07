package com.github.jaskelai.infobez

import java.math.BigInteger
import java.util.*

fun main() {
    val text = "HMMMMMM"
    val rsa = RSA(1024)
    val rsaServer = DummyRSAServer(rsa)

    val resultOfAttack = attack(rsa.encrypt(text.toByteArray().toBigInteger()).toByteArray(), rsaServer)
    println(resultOfAttack == text.toByteArray().toBigInteger())
}

// Реализация сервера, который расшифровывает сообщения
class DummyRSAServer(val rsa: RSA) {

    val publicKey = rsa.publicKey
    val incomingMsgStore = mutableSetOf<BigInteger>()

    fun decrypt(msg: ByteArray): BigInteger {
        val temp = msg.toBigInteger()

        return rsa.decrypt(temp).also { incomingMsgStore.add(temp) }
    }
}

// Реализация атаки на сервер
private fun attack(msgEnc: ByteArray, rsaServer: DummyRSAServer): BigInteger {

    // Экспонента и модуль
    val e = rsaServer.publicKey.first
    val n = rsaServer.publicKey.second

    // Генерируем s
    val s = generateRandomBigIntWithModulus(n - BigInteger.ONE)

    //C′ = ((S^E (mod N))C) (mod N)
    val r = (modExp(s, e, n) * msgEnc.toBigInteger()) % n

    val msgNew = rsaServer.decrypt(s.toByteArray())

    //P = P′/S (modN)
    return msgNew * s.modInverse(n) % n
}

// Возведение в степень по модулю
private fun modExp(base: BigInteger, exponent: BigInteger, module: BigInteger) = base.modPow(exponent, module)

private fun generateRandomBigIntWithModulus(modulus: BigInteger): BigInteger {
    val s = nextRandomBigInt(modulus)

    while (true) {
        if (s % modulus > BigInteger.ONE) return s
    }
}

private fun nextRandomBigInt(n: BigInteger): BigInteger {
    val rand = Random()
    var result = BigInteger(n.bitLength(), rand)
    while (result >= n) {
        result = BigInteger(n.bitLength(), rand)
    }
    return result
}

private fun ByteArray.toBigInteger() = BigInteger(this)
