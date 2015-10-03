import com.xteascala.XTEA
import org.scalatest._

class Complete extends FlatSpec with Matchers {
  "XTEA.key" should "Process a Array[Byte] passphrase and return a key" in {
    val rounds = 64
    val key = XTEA.key("0123456789abcdef".getBytes, rounds)
    key.length should be(rounds)
  }

  it should "Throw RuntimeException if the length of Array[Byte] passphrase is not 16" in {
    a[RuntimeException] should be thrownBy {
      XTEA.key("0123".getBytes)
    }
  }

  val random = new java.security.SecureRandom

  "XTEA.encryptCBC" should "Encrypt a message of size multiple of 8" in {
    val message = "Hello!!!"
    val iv = new Array[Byte](8)
    random.nextBytes(iv)
    XTEA.encryptCBC(message.getBytes("UTF-8"), iv, XTEA.key("0123456789abcdef".getBytes)).length % 8 should be(0)
  }

  it should "Encrypt a message of size not multiple of 8" in {
    val message = "Hello!!! çuláù ads"
    val iv = new Array[Byte](8)
    random.nextBytes(iv)
    XTEA.encryptCBC(message.getBytes("UTF-8"), iv, XTEA.key("0123456789abcdef".getBytes)).length % 8 should be(0)
  }

  it should "Throw RuntimeException if the length of Array[Byte] IV is not 8" in {
    val message = "Hello!!! çuláù ads"
    val iv = new Array[Byte](10)
    random.nextBytes(iv)
    a[RuntimeException] should be thrownBy {
      XTEA.encryptCBC(message.getBytes("UTF-8"), iv, XTEA.key("0123456789abcdef".getBytes))
    }
  }

  "XTEA.decryptCBC" should "Encrypt a message, decrypt the cipher generated and return the same previous message" in {
    val message = "Hello!!! çuláù ads"
    val key = XTEA.key("0123456789abcdef".getBytes)
    val iv = new Array[Byte](8)
    random.nextBytes(iv)
    val encrypted = XTEA.encryptCBC(message.getBytes("UTF-8"), iv, key)
    val decrypted = XTEA.decryptCBC(encrypted, iv, key)
    XTEA.toString(decrypted) should be(message)
  }

  it should "Throw RuntimeException if the length of Array[Byte] IV is not 8" in {
    val message = "Hello!!! çuláù ads"
    val key = XTEA.key("0123456789abcdef".getBytes)
    val iv = new Array[Byte](8)
    random.nextBytes(iv)
    val encrypted = XTEA.encryptCBC(message.getBytes("UTF-8"), iv, key)
    a[RuntimeException] should be thrownBy {
      val otheriv = new Array[Byte](10)
      random.nextBytes(otheriv)
      XTEA.decryptCBC(encrypted, otheriv, key)
    }
  }

  it should "Throw RuntimeException if the length of Array[Byte] data is not multiple of 8" in {
    val key = XTEA.key("0123456789abcdef".getBytes)
    val iv = new Array[Byte](8)
    random.nextBytes(iv)
    a[RuntimeException] should be thrownBy {
      XTEA.decryptCBC("014729049124712958".getBytes, iv, key)
    }
  }
}
