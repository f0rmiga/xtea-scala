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

import scala.collection.mutable.ListBuffer

object XTEA {
  private val DELTA = 0x9E3779B9

  /** Prepare the key to be used in encryption/decryption
    *
    * @param bytes 128-bit long random bytes to process xtea key
    * @param rounds Number of rounds
    * @return A sequence of Int's to be used in encryption/decryption as key
    */
  def key(bytes: Array[Byte], rounds: Int = 64): Seq[Int] = {
    if (bytes.length != 16) {
      throw new RuntimeException("The key must be 128-bit long")
    }
    val key = for (i <- 0 to 3) yield Seq((bytes(i * 4) & 0xFF) << 24, (bytes(i * 4 + 1) & 0xFF) << 16, (bytes(i * 4 + 2) & 0xFF) << 8, bytes(i * 4 + 3) & 0xFF).sum
    for (i <- 0 until rounds) yield if (i % 2 == 0) DELTA * (i / 2) + key(DELTA * (i / 2) & 3) else (DELTA * (i / 2) + DELTA) + key(((DELTA * (i / 2) + DELTA) >>> 11) & 3)
  }

  /** CBC block cipher mode
    *
    * @param data Byte array containing the data to encrypt, in case of String, it can be String.getBytes
    * @param iv Initialization vector
    * @param key The key used to encrypt
    * @param rounds Number of rounds
    * @return Encrypted byte array
    */
  def encryptCBC(data: Array[Byte], iv: Array[Byte], key: Seq[Int], rounds: Int = 64): Array[Byte] = {
    if (iv.length != 8) {
      throw new RuntimeException("The initialization vector must be 64-bit long")
    }

    val blocks: Seq[Array[Byte]] = for (i <- data.indices by 8) yield {
      if (i + 8 < data.length)
        data.slice(i, i + 8)
      else
        data.drop(i) ++ (for (i <- 0 to (7 - (data.length % 8))) yield 0x00.toByte)
    }
    val returnArray = new ListBuffer[Array[Byte]]
    blocks.foldLeft(iv)((lastBlock, block) => {
      val XORedBlock = (for (i <- 0 until 8) yield {
        (block(i) ^ lastBlock(i)).toByte
      }).toArray
      val encrypted = encryptBlock(XORedBlock, key, rounds)
      returnArray += encrypted
      encrypted
    })
    returnArray.foldLeft(Array[Byte]())(_ ++ _)
  }

  /** CBC block decipher mode
    *
    * @param data Byte array containing the encrypted data
    * @param key The key used to decrypt
    * @param rounds Number of rounds
    * @return Decrypted byte array
    */
  def decryptCBC(data: Array[Byte], iv: Array[Byte], key: Seq[Int], rounds: Int = 64): Array[Byte] = {
    if (iv.length != 8) {
      throw new RuntimeException("The initialization vector must be 64-bit long")
    }
    if (data.length % 8 != 0) {
      throw new RuntimeException("The data is not a CBC ciphered block")
    }

    val blocks: Seq[Array[Byte]] = for (i <- data.indices by 8) yield data.slice(i, i + 8)

    val returnBlocks = new ListBuffer[Array[Byte]]
    blocks.foldLeft(iv)((lastBlock, block) => {
      val decryptedBlock = decryptBlock(block, key, rounds)
      val XORedBlock = (for (i <- 0 until 8) yield {
        (decryptedBlock(i) ^ lastBlock(i)).toByte
      }).toArray
      returnBlocks += XORedBlock
      block
    })
    returnBlocks.foldLeft(Array[Byte]())(_ ++ _)
  }

  /** Encrypt 64-bit block
    *
    * @param block 64-bit block to encrypt
    * @param key The key used to encrypt
    * @param rounds Number of rounds
    * @return 64-bit encrypted block
    */
  def encryptBlock(block: Array[Byte], key: Seq[Int], rounds: Int): Array[Byte] = {
    val v0 = (block(0) << 24) | ((block(1) & 255) << 16) | ((block(2) & 255) << 8) | (block(3) & 255)
    val v1 = (block(4) << 24) | ((block(5) & 255) << 16) | ((block(6) & 255) << 8) | (block(7) & 255)
    val v = (0 until (rounds / 2)).foldLeft(v0, v1) {
      (last, i) =>
        val v0 = last._1 + ((((last._2 << 4) ^ (last._2 >>> 5)) + last._2) ^ key(i * 2))
        val v1 = last._2 + ((((v0 >>> 5) ^ (v0 << 4)) + v0) ^ key(i * 2 + 1))
        (v0, v1)
    }
    Array[Byte]((v._1 >> 24).toByte, (v._1 >> 16).toByte, (v._1 >> 8).toByte, v._1.toByte, (v._2 >> 24).toByte, (v._2 >> 16).toByte, (v._2 >> 8).toByte, v._2.toByte)
  }

  /** Decrypt 64-bit block
    *
    * @param block 64-bit block to decrypt
    * @param key The key used to decrypt
    * @param rounds Number of rounds
    * @return 64-bit decrypted block
    */
  def decryptBlock(block: Array[Byte], key: Seq[Int], rounds: Int): Array[Byte] = {
    val v1 = (block(4) << 24) | ((block(5) & 255) << 16) | ((block(6) & 255) << 8) | (block(7) & 255)
    val v0 = (block(0) << 24) | ((block(1) & 255) << 16) | ((block(2) & 255) << 8) | (block(3) & 255)
    val v = (((rounds / 2) - 1) to 0 by -1).foldLeft(v1, v0) {
      (last, i) =>
        val v1 = last._1 - ((((last._2 >>> 5) ^ (last._2 << 4)) + last._2) ^ key(i * 2 + 1))
        val v0 = last._2 - ((((v1 << 4) ^ (v1 >>> 5)) + v1) ^ key(i * 2))
        (v1, v0)
    }
    Array[Byte]((v._2 >> 24).toByte, (v._2 >> 16).toByte, (v._2 >> 8).toByte, v._2.toByte, (v._1 >> 24).toByte, (v._1 >> 16).toByte, (v._1 >> 8).toByte, v._1.toByte)
  }

  /** Extracts string from byte array and drop out null characters from end
    *
    * @param data Decrypted byte array to extract string
    * @param charset Charset
    * @return String from decrypted byte array
    */
  def toString(data: Array[Byte], charset: String = "UTF-8"): String = {
    new String(data.reverse.dropWhile(_ == 0x00).reverse, charset)
  }
}