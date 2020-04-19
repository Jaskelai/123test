import com.github.jaskelai.infobez.DiffieHellman33Case
import org.junit.Assert.assertEquals
import org.junit.Test

class DiffieHellman33CaseTest {

    private val alice = DiffieHellman33Case()
    private val bob = DiffieHellman33Case()

    @Test
    fun `test vectors assertion should be successful`() {

        val sessionKeyAlice = alice.getSessionKey(bob.publicKey)
        val sessionKeyBob = bob.getSessionKey(alice.publicKey)
        println(sessionKeyAlice)
        println(sessionKeyBob)

        assertEquals(sessionKeyAlice, sessionKeyBob)
    }
}