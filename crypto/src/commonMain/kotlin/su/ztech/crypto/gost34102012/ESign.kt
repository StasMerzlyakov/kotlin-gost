/*
 * Created by Stanislav Merzlyakov
 * st.merzlyakov@yandex.ru
 *  in May-2022.
 */

package su.ztech.crypto.gost34102012

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import su.ztech.crypto.ecurve.ECPoint
import su.ztech.crypto.ecurve.WeierstrassEllipticCurvesParamSet
import su.ztech.crypto.ecurve.bitCount
import su.ztech.crypto.ecurve.generateRandom
import su.ztech.crypto.ecurve.multiply
import su.ztech.crypto.ecurve.plus

fun signGen(
    e: BigInteger, // Хэш
    d: BigInteger, // Закрытый ключ
    paramSet: WeierstrassEllipticCurvesParamSet,
    k: BigInteger = generateRandom(paramSet.q)
): String {
    var r: BigInteger
    var s: BigInteger
    var c = multiply(k, paramSet)
    val q = paramSet.q
    r = c.x % q
    s = ((r * d) + (k * e)) % q

    if (r.equals(0) || s.equals(0)) {
        do {
            val k2 = generateRandom(q)
            c = multiply(k2, paramSet)
            r = c.x % q
            s = ((r * d) + (k2 * e)) % q
        } while (r.equals(0) || s.equals(0))
    }

    val len = q.bitCount() / 4
    val rVector = r.toString(16).padStart(len, '0')
    val sVector = s.toString(16).padStart(len, '0')

    return "$rVector$sVector"
}

fun signGen(
    hash: UByteArray, // Хэш
    d: BigInteger, // Закрытый ключ
    paramSet: WeierstrassEllipticCurvesParamSet
): String {
    val alpha = BigInteger.fromUByteArray(hash, Sign.POSITIVE)
    val q = paramSet.q
    var e = alpha % q
    if (e.equals(0)) {
        e += 1
    }
    return signGen(e, d, paramSet)
}

fun signValidate(
    e: BigInteger, // Хэш
    r: BigInteger,
    s: BigInteger,
    publicKey: ECPoint, // Ключ проверки ЭП
    paramSet: WeierstrassEllipticCurvesParamSet
): Boolean {
    val q = paramSet.q
    var v = e.modInverse(q)
    if (v < 0) {
        v += q
    }

    val z1 = (s * v) % q
    val z2 = q - (r * v) % q
    val pointA = multiply(z1, paramSet)
    val pointB = multiply(publicKey, z2, paramSet)
    val pointC = plus(pointA, pointB, paramSet)

    val rS = pointC.x % q
    return rS == r
}

fun signValidate(
    hash: UByteArray, // Хэш
    eSign: String, // Значение ЭП
    publicKey: ECPoint, // Ключ проверки ЭП
    paramSet: WeierstrassEllipticCurvesParamSet
): Boolean {
    val q = paramSet.q
    val len = q.bitCount() / 4
    val rVectorStr = eSign.substring(0, len)
    val sVectorStr = eSign.substring(len, 2 * len)

    val r = BigInteger.parseString(rVectorStr, 16)
    val s = BigInteger.parseString(sVectorStr, 16)

    if (r >= q || s >= q) return false

    val alpha = BigInteger.fromUByteArray(hash, Sign.POSITIVE)
    var e = alpha % q
    if (e.equals(0)) {
        e += 1
    }
    return signValidate(e, r, s, publicKey, paramSet)
}
