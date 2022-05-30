/*
 * Created by Stanislav Merzlyakov
 * st.merzlyakov@yandex.ru
 *  in May-2022.
 */

package su.ztech.crypto

import su.ztech.crypto.ecurve.WeierstrassEllipticCurvesParamSet
import su.ztech.crypto.gost34112012.Hash256
import su.ztech.crypto.gost34112012.Hash512
import su.ztech.crypto.p5011142016.GOST_3110_12_256_ParamSetA
import su.ztech.crypto.p5011142016.GOST_3110_12_512_ParamSetA
import su.ztech.crypto.p5011142016.GOST_3110_12_512_ParamSetB
import su.ztech.crypto.p5011142016.GOST_3110_12_512_ParamSetC
import su.ztech.crypto.rfc4357.GOST_3110_2001_CRYPTOPRO_A_PARAM_SET
import su.ztech.crypto.rfc4357.GOST_3110_2001_CRYPTOPRO_B_PARAM_SET
import su.ztech.crypto.rfc4357.GOST_3110_2001_CRYPTOPRO_C_PARAM_SET

const val OID_GOST_3410_2012_256 = "1.2.643.7.1.1.2.2"
const val OID_GOST_3410_2012_256_NAME = "id-tc26-gost3411-12-256"

const val OID_GOST_3410_2012_512 = "1.2.643.7.1.1.2.3"
const val OID_GOST_3410_2012_512_NAME = "id-tc26-gost3411-12-512"

const val OID_GOST_3110_2012_512_PARAM_SET_A = "1.2.643.7.1.2.1.2.1"
const val OID_GOST_3110_2012_512_PARAM_SET_A_NAME = "id-tc26-gost-3410-12-512-paramSetA"

const val OID_GOST_3110_2012_512_PARAM_SET_B = "1.2.643.7.1.2.1.2.2"
const val OID_GOST_3110_2012_512_PARAM_SET_B_NAME = "id-tc26-gost-3410-12-512-paramSetB"

const val OID_GOST_3110_2012_512_PARAM_SET_C = "1.2.643.7.1.2.1.2.3"
const val OID_GOST_3110_2012_512_PARAM_SET_C_NAME = "id-tc26-gost-3410-12-512-paramSetC"

const val OID_GOST_3110_2012_256_PARAM_SET_A = "1.2.643.7.1.2.1.1.1"
const val OID_GOST_3110_2012_256_PARAM_SET_A_NAME = "id-tc26-gost-3410-2012-256-paramSetA"

const val OID_GOST_3110_2001_CRYPTOPRO_A_PARAM_SET = "1.2.643.2.2.35.1"
const val OID_GOST_3110_2001_CRYPTOPRO_A_PARAM_SET_NAME = "id-GostR3410-2001-CryptoPro-A-ParamSet"

const val OID_GOST_3110_2001_CRYPTOPRO_B_PARAM_SET = "1.2.643.2.2.35.2"
const val OID_GOST_3110_2001_CRYPTOPRO_B_PARAM_SET_NAME = "id-GostR3410-2001-CryptoPro-B-ParamSet"

const val OID_GOST_3110_2001_CRYPTOPRO_C_PARAM_SET = "1.2.643.2.2.35.3"
const val OID_GOST_3110_2001_CRYPTOPRO_C_PARAM_SET_NAME = "id-GostR3410-2001-CryptoPro-C-ParamSet"

fun getGost34102012ParamSet(oidOrName: String): WeierstrassEllipticCurvesParamSet =
    when (oidOrName) {
        OID_GOST_3110_2012_512_PARAM_SET_A, OID_GOST_3110_2012_512_PARAM_SET_A_NAME -> GOST_3110_12_512_ParamSetA
        OID_GOST_3110_2012_512_PARAM_SET_B, OID_GOST_3110_2012_512_PARAM_SET_B_NAME -> GOST_3110_12_512_ParamSetB
        OID_GOST_3110_2012_512_PARAM_SET_C, OID_GOST_3110_2012_512_PARAM_SET_C_NAME -> GOST_3110_12_512_ParamSetC
        OID_GOST_3110_2012_256_PARAM_SET_A, OID_GOST_3110_2012_256_PARAM_SET_A_NAME -> GOST_3110_12_256_ParamSetA
        OID_GOST_3110_2001_CRYPTOPRO_A_PARAM_SET, OID_GOST_3110_2001_CRYPTOPRO_A_PARAM_SET_NAME -> GOST_3110_2001_CRYPTOPRO_A_PARAM_SET
        OID_GOST_3110_2001_CRYPTOPRO_B_PARAM_SET, OID_GOST_3110_2001_CRYPTOPRO_B_PARAM_SET_NAME -> GOST_3110_2001_CRYPTOPRO_B_PARAM_SET
        OID_GOST_3110_2001_CRYPTOPRO_C_PARAM_SET, OID_GOST_3110_2001_CRYPTOPRO_C_PARAM_SET_NAME -> GOST_3110_2001_CRYPTOPRO_C_PARAM_SET
        else -> throw AssertionError("unsupported algorithm id $oidOrName")
    }

fun getPbkdf2Len(oidOrName: String): Int = when (oidOrName) {
    OID_GOST_3110_2012_512_PARAM_SET_A, OID_GOST_3110_2012_512_PARAM_SET_A_NAME,
    OID_GOST_3110_2012_512_PARAM_SET_B, OID_GOST_3110_2012_512_PARAM_SET_B_NAME,
    OID_GOST_3110_2012_512_PARAM_SET_C, OID_GOST_3110_2012_512_PARAM_SET_C_NAME -> 512
    OID_GOST_3110_2001_CRYPTOPRO_A_PARAM_SET, OID_GOST_3110_2001_CRYPTOPRO_A_PARAM_SET_NAME,
    OID_GOST_3110_2001_CRYPTOPRO_B_PARAM_SET, OID_GOST_3110_2001_CRYPTOPRO_B_PARAM_SET_NAME,
    OID_GOST_3110_2001_CRYPTOPRO_C_PARAM_SET, OID_GOST_3110_2001_CRYPTOPRO_C_PARAM_SET_NAME,
    OID_GOST_3110_2012_256_PARAM_SET_A, OID_GOST_3110_2012_256_PARAM_SET_A_NAME -> 256
    else -> throw AssertionError("unsupported algorithm id $oidOrName")
}

fun getGostHash(oidOrName: String, input: UByteArray): UByteArray {
    return when (oidOrName) {
        OID_GOST_3410_2012_256, OID_GOST_3410_2012_256_NAME -> {
            val hash = Hash256()
            hash.final(input).h
        }
        OID_GOST_3410_2012_512, OID_GOST_3410_2012_512_NAME -> {
            val hash = Hash512()
            hash.final(input).h
        }
        else -> throw AssertionError("unsupported algorithm id $oidOrName")
    }
}

fun String.toUByteArray(): UByteArray = encodeToByteArray().toUByteArray()

operator fun UByteArray.get(idx: UByte): UByte {
    return this[idx.toInt()]
}

operator fun UIntArray.get(idx: UInt): UInt {
    return this[idx.toInt()]
}

typealias KeyPair = Pair<UByteArray, UByteArray>

interface Encryptor {
    fun encrypt(message: UByteArray): UByteArray
}

fun xor(a: UByteArray, b: UByteArray): UByteArray {
    val c = UByteArray(a.size)
    a.forEachIndexed { index, _ ->
        c[index] = a[index] xor b[index]
    }
    return c
}
