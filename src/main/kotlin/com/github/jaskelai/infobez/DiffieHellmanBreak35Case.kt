package com.github.jaskelai.infobez

import org.apache.commons.codec.binary.Hex
import java.math.BigInteger

fun main() {

    val res1 = DiffieHellmanBreak35Case().execute("1")
    val res2 = DiffieHellmanBreak35Case().execute(BigInteger(DiffieHellman33Case.P_HASH, 16).toString())
    val res3 = DiffieHellmanBreak35Case().execute(
        BigInteger(
            DiffieHellman33Case.P_HASH,
            16
        ).subtract(BigInteger.valueOf(1)).toString()
    )

    println("${res1 == res2}")
    println("${res2 == res3}")
}

class DiffieHellmanBreak35Case {

    fun execute(g: String): String {

        val alice = DiffieHellman33Case()
        val bob = DiffieHellman33Case()
        bob.g = BigInteger(g)

        // отправляем p и g от Alice
        val p = alice.p

        // Alice отправляет A к Bob
        var aAlice = alice.publicKey
        // М перехватывает запрос, заменяет A на p и отправлет к Bob
        aAlice = p

        // отправляем A от Bob к Alice
        var aBob = bob.publicKey

        // Alice отправляет зашифрованное сообщение к Bob
        val message = "still goodd".toByteArray()
        val keyAlice = Hex.decodeHex(getSha1Hash(alice.getSessionKey(aBob).toString())).take(BLOCK_SIZE).toByteArray()
        val ivAlice = generateByteArray(BLOCK_SIZE)
        val encryptedMessageByAlice = aesCbcEncrypt(input = message, key = keyAlice, iv = ivAlice) + ivAlice

        // MITM расшифровывает сообщение от Alice
        val ivAliceByMitm = encryptedMessageByAlice.takeLast(BLOCK_SIZE).toByteArray()

        val hackedMessage = when (g) {
            "1" -> {
                val hackedKey = Hex.decodeHex(getSha1Hash("1")).take(BLOCK_SIZE).toByteArray()
                aesCbcDecrypt(
                    input = encryptedMessageByAlice.dropLast(BLOCK_SIZE).toByteArray(),
                    key = hackedKey,
                    iv = ivAliceByMitm
                )
            }
            p.toString() -> {
                val hackedKey = Hex.decodeHex(getSha1Hash("0")).take(BLOCK_SIZE).toByteArray()
                aesCbcDecrypt(
                    input = encryptedMessageByAlice.dropLast(BLOCK_SIZE).toByteArray(),
                    key = hackedKey,
                    iv = ivAliceByMitm
                )
            }
            (p.subtract(BigInteger.valueOf(1))).toString() -> {
                var hackedMessage = ByteArray(0)
                for (x in arrayListOf("1", p.subtract(BigInteger.valueOf(1)).toString())) {
                    val hackedKey = Hex.decodeHex(getSha1Hash(x)).take(BLOCK_SIZE).toByteArray()

                    hackedMessage = aesCbcDecrypt(
                        input = encryptedMessageByAlice.dropLast(BLOCK_SIZE).toByteArray(),
                        key = hackedKey,
                        iv = ivAliceByMitm
                    )

                    if (hackedMessage.none().not()) break
                }
                hackedMessage
            }
            else -> ByteArray(0)
        }
        return Hex.encodeHexString(hackedMessage)
    }
}