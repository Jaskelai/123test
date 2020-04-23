package com.github.jaskelai.infobez

import org.apache.commons.codec.binary.Hex
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

const val BLOCK_SIZE = 16

class DiffieHellmanMITM34Case {

    fun execute(alice: DiffieHellman33Case, bob: DiffieHellman33Case): Triple<ByteArray, ByteArray, ByteArray> {

        val p = alice.p
        val g = alice.g

        // отправляем A от Alice к Bob
        var aAlice = alice.publicKey
        // М перехватывает запрос, заменяет A на p и отправлет к Bob
        aAlice = p

        // отправляем A от Bob к Alice
        var aBob = bob.publicKey
        // М перехватывает запрос, заменяет A на p и отправлет к Alice
        aBob = p

        // Alice отправляет зашифрованное сообщение к Bob
        val message = "I LOVE KOTLIN".toByteArray()
        val keyAlice = Hex.decodeHex(getSha1Hash(alice.getSessionKey(aBob).toString())).take(BLOCK_SIZE).toByteArray()
        val ivAlice = generateByteArray(BLOCK_SIZE)
        val encryptedMessageByAlice = aesCbcEncrypt(input = message, key = keyAlice, iv = ivAlice) + ivAlice

        // Bob расшифровывает сообщение, отправленное от Alice и отправляет снова к Alice
        val keyBob = Hex.decodeHex(getSha1Hash(bob.getSessionKey(aAlice).toString())).take(BLOCK_SIZE).toByteArray()
        val ivAliceByBob = encryptedMessageByAlice.takeLast(BLOCK_SIZE).toByteArray()
        val decryptedMessage = aesCbcDecrypt(
            input = encryptedMessageByAlice.dropLast(BLOCK_SIZE).toByteArray(),
            key = keyBob,
            iv = ivAliceByBob
        )
        val ivBob = generateByteArray(BLOCK_SIZE)
        val encryptedAnswerByBob = aesCbcEncrypt(input = decryptedMessage, key = keyBob, iv = ivBob) + ivBob

        // на стороне MITM расшифровываем значения
        val hackedKey = Hex.decodeHex(getSha1Hash("0")).take(BLOCK_SIZE).toByteArray()

        val aliceIv = encryptedMessageByAlice.takeLast(BLOCK_SIZE).toByteArray()
        val hackedAliceMessage = aesCbcDecrypt(
            input = encryptedMessageByAlice.dropLast(BLOCK_SIZE).toByteArray(),
            key = hackedKey,
            iv = aliceIv
        )

        val bobIv = encryptedAnswerByBob.takeLast(BLOCK_SIZE).toByteArray()
        val hackedBobMessage = aesCbcDecrypt(
            input = encryptedAnswerByBob.dropLast(BLOCK_SIZE).toByteArray(),
            key = hackedKey,
            iv = bobIv
        )

        return Triple(message, hackedAliceMessage, hackedBobMessage)
    }
}

fun getSha1Hash(input: String): String {
    val digest = MessageDigest.getInstance("SHA-1")
    val result = digest.digest(input.toByteArray())

    val sb = StringBuilder()

    for (b in result) {
        sb.append(String.format("%02X", b))
    }

    return sb.toString()
}

fun generateByteArray(size: Int): ByteArray {
    val byteArray = ByteArray(size)
    SecureRandom.getInstanceStrong().nextBytes(byteArray)
    return byteArray
}

// AES + CBC шифрование
fun aesCbcEncrypt(input: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
    val aesKey = SecretKeySpec(key, "AES")
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, aesKey, IvParameterSpec(iv))
    return cipher.doFinal(input)
}

// AES + CBC дешифрование
fun aesCbcDecrypt(input: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
    val aesKey = SecretKeySpec(key, "AES")
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.DECRYPT_MODE, aesKey, IvParameterSpec(iv))
    return cipher.doFinal(input)
}
