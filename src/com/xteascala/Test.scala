/* The MIT License (MIT)
 *
 * Copyright (c) 2015 Thulio Ferraz Assis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

package com.xteascala

object Test extends App {
  val testStart = System.nanoTime
  (1 to 10000).foreach(i => {
    println(s"$i.")
    // 1. Generate some random bytes
    val random = new java.security.SecureRandom
    val bytes = new Array[Byte](16)
    random.nextBytes(bytes)

    // 2. Get the key to process
    val key = XTEA.key(bytes)

    // 3. Get the IV
    val iv = new Array[Byte](8)
    random.nextBytes(iv)

    // 4. Encrypt some string
    val s1 = System.nanoTime
    val toEncrypt = "Hello! Olá! úóíûàç す文字列"
    val encrypted = XTEA.encryptCBC(toEncrypt.getBytes("UTF-8"), iv, key)
    println(s"Encryption took ${(System.nanoTime - s1) / 1e6}ms")

    // 5. Decrypt the encrypted data
    val s2 = System.nanoTime
    val decrypted = XTEA.decryptCBC(encrypted, iv, key)
    println(s"Decryption took ${(System.nanoTime - s2) / 1e6}ms\n\n")

    // 6. Compare the pre-encrypted string and decrypted string
    assert(toEncrypt == XTEA.toString(decrypted))
  })
  println(s"Test took ${(System.nanoTime - testStart) / 1e6}ms")
}