/*
 * Created by Stanislav Merzlyakov
 * st.merzlyakov@yandex.ru
 *  in May-2022.
 */

package su.ztech.crypto.gost34122008

import su.ztech.crypto.Encryptor
import su.ztech.crypto.KeyPair
import su.ztech.crypto.get
import su.ztech.crypto.xor

const val MAGMA_BLOCK_SIZE = 8

/**
 * TODO optimize с UInt
 */

private val P0 = uintArrayOf(12u, 4u, 6u, 2u, 10u, 5u, 11u, 9u, 14u, 8u, 13u, 7u, 0u, 3u, 15u, 1u)
private val P1 = uintArrayOf(6u, 8u, 2u, 3u, 9u, 10u, 5u, 12u, 1u, 14u, 4u, 7u, 1u, 13u, 0u, 15u)
private val P2 = uintArrayOf(11u, 3u, 5u, 8u, 2u, 15u, 10u, 13u, 14u, 1u, 7u, 4u, 12u, 9u, 6u, 0u)
private val P3 = uintArrayOf(12u, 8u, 2u, 1u, 13u, 4u, 15u, 6u, 7u, 0u, 10u, 5u, 3u, 14u, 9u, 11u)
private val P4 = uintArrayOf(7u, 15u, 5u, 10u, 8u, 1u, 6u, 13u, 0u, 9u, 3u, 14u, 11u, 4u, 2u, 12u)
private val P5 = uintArrayOf(5u, 13u, 15u, 6u, 9u, 2u, 12u, 10u, 11u, 7u, 8u, 1u, 4u, 3u, 14u, 0u)
private val P6 = uintArrayOf(8u, 14u, 2u, 5u, 6u, 9u, 1u, 12u, 15u, 4u, 11u, 0u, 13u, 10u, 3u, 7u)
private val P7 = uintArrayOf(1u, 7u, 14u, 13u, 0u, 5u, 8u, 3u, 4u, 15u, 10u, 6u, 9u, 12u, 11u, 2u)

fun gostT(a: UByteArray) {
    val b = uintArrayOf(
        a[0].toUInt() and 0xf0u shr 4,
        a[0].toUInt() and 0x0fu,
        a[1].toUInt() and 0xf0u shr 4,
        a[1].toUInt() and 0x0fu,
        a[2].toUInt() and 0xf0u shr 4,
        a[2].toUInt() and 0x0fu,
        a[3].toUInt() and 0xf0u shr 4,
        a[3].toUInt() and 0x0fu
    )

    b[0] = P7[b[0]]
    b[1] = P6[b[1]]
    b[2] = P5[b[2]]
    b[3] = P4[b[3]]
    b[4] = P3[b[4]]
    b[5] = P2[b[5]]
    b[6] = P1[b[6]]
    b[7] = P0[b[7]]

    a[0] = ((b[0] shl 4) + (b[1] and 0x0fu)).toUByte()
    a[1] = ((b[2] shl 4) + (b[3] and 0x0fu)).toUByte()
    a[2] = ((b[4] shl 4) + (b[5] and 0x0fu)).toUByte()
    a[3] = ((b[6] shl 4) + (b[7] and 0x0fu)).toUByte()
}

fun gostAdd32(a: UByteArray, b: UByteArray, c: UByteArray) {
    var internal: UInt = 0u
    for (index in MAGMA_BLOCK_SIZE / 2 - 1 downTo 0) {
        internal = a[index] + b[index] + (internal shr 8)
        c[index] = (internal and 0xffu).toUByte()
    }
}

fun gostg(k: UByteArray, a: UByteArray): UByteArray {
    val result = UByteArray(MAGMA_BLOCK_SIZE / 2)
    gostAdd32(a, k, result) // сложение над полем Z32
    gostT(result)
    var ch = (result[0].toUInt() shl 24) + (result[1].toUInt() shl 16) + (result[2].toUInt() shl 8) + result[3].toUInt()
    ch = ((ch shl 11) + (ch and 0xffe00000u shr 21))
    result[0] = (ch shr 24).toUByte()
    result[1] = (ch shr 16).toUByte()
    result[2] = (ch shr 8).toUByte()
    result[3] = ch.toUByte()
    return result
}

fun gostG(k: UByteArray, pair: Pair<UByteArray, UByteArray>): Pair<UByteArray, UByteArray> {
    return Pair(pair.second, xor(gostg(k, pair.second), pair.first))
}

fun createIterationKeys(keyPair: KeyPair): Map<Int, UByteArray> = mapOf(
    1 to keyPair.first.copyOfRange(0, 4),
    2 to keyPair.first.copyOfRange(4, 8),
    3 to keyPair.first.copyOfRange(8, 12),
    4 to keyPair.first.copyOfRange(12, 16),
    5 to keyPair.second.copyOfRange(0, 4),
    6 to keyPair.second.copyOfRange(4, 8),
    7 to keyPair.second.copyOfRange(8, 12),
    8 to keyPair.second.copyOfRange(12, 16),

    9 to keyPair.first.copyOfRange(0, 4),
    10 to keyPair.first.copyOfRange(4, 8),
    11 to keyPair.first.copyOfRange(8, 12),
    12 to keyPair.first.copyOfRange(12, 16),
    13 to keyPair.second.copyOfRange(0, 4),
    14 to keyPair.second.copyOfRange(4, 8),
    15 to keyPair.second.copyOfRange(8, 12),
    16 to keyPair.second.copyOfRange(12, 16),

    17 to keyPair.first.copyOfRange(0, 4),
    18 to keyPair.first.copyOfRange(4, 8),
    19 to keyPair.first.copyOfRange(8, 12),
    20 to keyPair.first.copyOfRange(12, 16),
    21 to keyPair.second.copyOfRange(0, 4),
    22 to keyPair.second.copyOfRange(4, 8),
    23 to keyPair.second.copyOfRange(8, 12),
    24 to keyPair.second.copyOfRange(12, 16),

    25 to keyPair.second.copyOfRange(12, 16),
    26 to keyPair.second.copyOfRange(8, 12),
    27 to keyPair.second.copyOfRange(4, 8),
    28 to keyPair.second.copyOfRange(0, 4),

    29 to keyPair.first.copyOfRange(12, 16),
    30 to keyPair.first.copyOfRange(8, 12),
    31 to keyPair.first.copyOfRange(4, 8),
    32 to keyPair.first.copyOfRange(0, 4)
)

class Magma(keyPair: KeyPair) : Encryptor {

    private val keyMap = createIterationKeys(keyPair)

    override fun encrypt(message: UByteArray): UByteArray {
        var pair = Pair(message.copyOf(MAGMA_BLOCK_SIZE / 2), message.copyOfRange(MAGMA_BLOCK_SIZE / 2, MAGMA_BLOCK_SIZE))
        for (i in 1..32) {
            pair = gostG(keyMap[i]!!, pair)
        }

        val result = UByteArray(MAGMA_BLOCK_SIZE)
        pair.second.copyInto(result)
        pair.first.copyInto(result, MAGMA_BLOCK_SIZE / 2, 0, MAGMA_BLOCK_SIZE / 2)
        return result
    }

    fun decrypt(a: UByteArray): UByteArray {
        var pair = Pair(a.copyOf(MAGMA_BLOCK_SIZE / 2), a.copyOfRange(MAGMA_BLOCK_SIZE / 2, MAGMA_BLOCK_SIZE))
        for (i in 32 downTo 1) {
            pair = gostG(keyMap[i]!!, pair)
        }
        val result = UByteArray(MAGMA_BLOCK_SIZE)
        pair.second.copyInto(result)
        pair.first.copyInto(result, MAGMA_BLOCK_SIZE / 2, 0, MAGMA_BLOCK_SIZE / 2)
        return result
    }
}
