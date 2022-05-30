/*
 * Created by Stanislav Merzlyakov
 * st.merzlyakov@yandex.ru
 *  in May-2022.
 */

package su.ztech.sespake.p5011112016

import su.ztech.crypto.gost34112012.BLOCK_SIZE
import su.ztech.crypto.toUByteArray
import su.ztech.crypto.xor
import su.ztech.sespake.p5011132016.hmacGostR34112012512

fun pbkdf2(pArray: UByteArray, sArray: UByteArray, c: Int, dkLen: Int): UByteArray {

    val n = ceil(dkLen, BLOCK_SIZE)
    val result = UByteArray(n * BLOCK_SIZE)

    for (i in 0 until n) {
        var u = hmacGostR34112012512(pArray, sArray + int(i + 1))
        var t = u
        for (j in 1 until c) {
            u = hmacGostR34112012512(pArray, u)
            t = xor(t, u)
        }
        t.copyInto(result, i * BLOCK_SIZE)
    }
    return result.copyOfRange(0, dkLen)
}

private fun ceil(dividend: Int, divider: Int): Int = when (dividend % divider) {
    0 -> dividend / divider
    else -> dividend / divider + 1
}

fun pbkdf2(p: String, s: String, c: Int, dkLen: Int): UByteArray {
    val pArray = p.toUByteArray()
    val sArray = s.toUByteArray()
    return pbkdf2(pArray, sArray, c, dkLen)
}

private fun int(i: Int): UByteArray {
    val ui = i.toUInt()
    val i4 = (ui and 0xff000000u) shr 24
    val i3 = (ui and 0x00ff0000u) shr 16
    val i2 = (ui and 0x0000ff00u) shr 8
    val i1 = (ui and 0x000000ffu)
    return ubyteArrayOf(i4.toUByte(), i3.toUByte(), i2.toUByte(), i1.toUByte())
}
