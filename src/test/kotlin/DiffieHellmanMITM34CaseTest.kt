import com.github.jaskelai.infobez.DiffieHellman33Case
import com.github.jaskelai.infobez.DiffieHellmanMITM34Case
import org.junit.Assert.assertArrayEquals
import org.junit.Test

class DiffieHellmanMITM34CaseTest {

    private val case = DiffieHellmanMITM34Case()
    private val alice = DiffieHellman33Case()
    private val bob = DiffieHellman33Case()

    @Test
    fun `test vectors assertion should be successful`() {
        val result = case.execute(alice, bob)
        val message = result.first
        val aliceDecrypted = result.second
        val bobDecrypted = result.third

        assertArrayEquals(message, aliceDecrypted)
        assertArrayEquals(message, bobDecrypted)
    }
}