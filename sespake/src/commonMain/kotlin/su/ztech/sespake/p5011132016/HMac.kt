/*
 * Created by Stanislav Merzlyakov
 * st.merzlyakov@yandex.ru
 *  in May-2022.
 */

package su.ztech.sespake.p5011132016

import su.ztech.crypto.OID_GOST_3410_2012_256
import su.ztech.crypto.OID_GOST_3410_2012_512
import su.ztech.crypto.getGostHash
import su.ztech.crypto.xor

fun hmacGostR34112012256(key: UByteArray, t: UByteArray): UByteArray =
    hmac(key, t) { toHash -> getGostHash(OID_GOST_3410_2012_256, toHash) }

fun hmacGostR34112012512(key: UByteArray, t: UByteArray): UByteArray =
    hmac(key, t) { toHash -> getGostHash(OID_GOST_3410_2012_512, toHash) }

private fun expandKey(input: UByteArray): UByteArray {
    if (input.size == KEY_MAX_VALUE_IN_BYTES)
        return input
    val output = UByteArray(KEY_MAX_VALUE_IN_BYTES)
    input.copyInto(output)
    return output
}

private fun hmac(key: UByteArray, t: UByteArray, hashFn: (UByteArray) -> UByteArray): UByteArray {
    val kk = expandKey(key)
    val part1 = xor(kk, ipad)
    val toHash1 = part1 + t
    val hashValue1 = hashFn(toHash1)
    val part2 = xor(kk, opad)
    val toHash2 = part2 + hashValue1
    return hashFn(toHash2)
}

private const val KEY_MAX_VALUE_IN_BYTES = 64

private val ipad = UByteArray(KEY_MAX_VALUE_IN_BYTES) { 0x36u }
private val opad = UByteArray(KEY_MAX_VALUE_IN_BYTES) { 0x5cu }
