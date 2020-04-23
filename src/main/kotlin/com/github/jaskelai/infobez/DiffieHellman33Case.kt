package com.github.jaskelai.infobez

import java.math.BigInteger
import java.util.*

class DiffieHellman33Case {

    companion object {
        const val G = 2
        const val P_HASH = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"
    }

    // g - начальное значение g
    var g: BigInteger = BigInteger.valueOf(G.toLong())

    // p - начальное значение p
    val p = BigInteger(P_HASH, 16)

    // a - секретный ключ
    private val secretKey: BigInteger = nextRandomBigInt(p)

    // А - публичный ключ
    val publicKey: BigInteger
        get() {
            return modExp(
                base = g,
                exponent = secretKey,
                module = p
            )
        }

    // s - сессионный ключ
    fun getSessionKey(other: BigInteger): BigInteger = modExp(
        base = other,
        exponent = secretKey,
        module = p
    )

    // Возведение в степень по модулю
    private fun modExp(base: BigInteger, exponent: BigInteger, module: BigInteger) = base.modPow(exponent, module)

    // Генерация a
    private fun nextRandomBigInt(n: BigInteger): BigInteger {
        val rand = Random()
        var result = BigInteger(n.bitLength(), rand)
        while (result >= n) {
            result = BigInteger(n.bitLength(), rand)
        }
        return result
    }
}
