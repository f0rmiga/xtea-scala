# XTEA for Scala
Implementation in Scala language of XTEA and CBC block cipher mode of operation.

## Usage
```scala
val someBytes: Array[Byte] = "0123456789abcdef".getBytes // 128-bit long
val xteaKey: Seq[Int] = XTEA.key(someBytes) // Key computed to be used in encryption/decryption
val random = new java.security.SecureRandom
val iv = new Array[Byte](8) // Initialization vector for CBC mode
random.nextBytes(iv)
val message: String = "Something to encrypt" // String to encrypt
val encrypted: Array[Byte] = XTEA.encryptCBC(message.getBytes("UTF-8"), iv, xteaKey) // Perform encryption
val decrypted: Array[Byte] = XTEA.decryptCBC(encrypted, iv, xteaKey) // Perform decryption
assert(message == XTEA.toString(decrypted)) // Compare not encrypted string to decrypted string
```

## Documentation
Look at the source code, it is well documented.

## License
MIT License.
