/*
 * Created by Stanislav Merzlyakov
 * st.merzlyakov@yandex.ru
 *  in May-2022.
 */

package su.ztech.crypto.ecurve

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import kotlin.random.Random
import kotlin.random.nextUBytes

data class ECPoint(val x: BigInteger, val y: BigInteger)

val ECPointZero = ECPoint(BigInteger.ZERO, BigInteger.ZERO)

data class WeierstrassEllipticCurvesParamSet(
    val p: BigInteger, // модуль эллиптической кривой
    val a: BigInteger, // коэффициент a уравнения эллиптической кривой
    val b: BigInteger, // коэффициент b уравнения эллиптической кривой
    val m: BigInteger, // порядок группы точек эллиптической кривой
    val q: BigInteger, // порядок циклической подгруппы точек эллиптической кривой
    val P: ECPoint // координаты точки P (порождающего элемента подгруппы порядка q) на эллиптической кривой в канонической форме
)

fun pointToUByteArrayLE(p: ECPoint): UByteArray = (p.y.toUByteArray() + p.x.toUByteArray()).reversedArray()

fun pointToUByteArrayBE(p: ECPoint): UByteArray = (p.x.toUByteArray() + p.y.toUByteArray())

fun pointToUByteArray(p: ECPoint, curvesParamSet: WeierstrassEllipticCurvesParamSet): UByteArray {

    // Определяем длину по p
    val len = curvesParamSet.p.numberOfWords * 32
    val result = UByteArray(2 * len)
    val px = p.x.toUByteArray()
    px.copyInto(result, len - px.size)

    val py = p.y.toUByteArray()
    py.copyInto(result, 2 * len - py.size)
    return result
}

fun plus(p1: ECPoint, p2: ECPoint, paramSet: WeierstrassEllipticCurvesParamSet): ECPoint =
    plus(p1, p2, paramSet.a, paramSet.b, paramSet.p)

fun plus(p1: ECPoint, p2: ECPoint, a: BigInteger, b: BigInteger, p: BigInteger): ECPoint {

    if (p1.x != p2.x) {
        var dy = p2.y - p1.y
        if (dy < 0)
            dy += p

        var dx = p2.x - p1.x
        if (dx < 0)
            dx += p

        // разделить на x все равно что умножить на x^-1
        var lmbd = (dy * dx.modInverse(p)) % p
        if (lmbd < 0) {
            lmbd += p
        }

        var x = (lmbd * lmbd - p1.x - p2.x) % p
        if (x < 0) {
            x += p
        }

        var y = (lmbd * (p1.x - x) - p1.y) % p
        if (y < 0) {
            y += p
        }
        return ECPoint(x, y)
    } else {
        if (p1.y == p2.y) {
            // Удвоение точки
            var lmbd = (p1.x * p1.x * 3 + a) % p
            if (lmbd < 0) {
                lmbd += p
            }
            lmbd *= (p1.y * 2).modInverse(p)

            var x = (lmbd * lmbd - p1.x - p1.x) % p
            if (x < 0) {
                x += p
            }

            var y = (lmbd * (p1.x - x) - p1.y) % p
            if (y < 0) {
                y += p
            }
            return ECPoint(x, y)
        } else {
            // Точки лежат на кривой => если x1 == x2 и y1!=y2 то y1 == -y2
            return ECPointZero // Нулевая точка
        }
    }
}

fun minus(p1: ECPoint, p2: ECPoint, paramSet: WeierstrassEllipticCurvesParamSet): ECPoint =
    minus(p1, p2, paramSet.a, paramSet.b, paramSet.p)

fun minus(p1: ECPoint, p2: ECPoint, a: BigInteger, b: BigInteger, p: BigInteger): ECPoint =
    plus(p1, ECPoint(p2.x, -p2.y), a, b, p)

fun double(ecP: ECPoint, paramSet: WeierstrassEllipticCurvesParamSet): ECPoint =
    double(ecP, paramSet.a, paramSet.b, paramSet.p)

fun double(ecP: ECPoint, a: BigInteger, b: BigInteger, p: BigInteger): ECPoint = plus(ecP, ecP, a, b, p)

fun multiply(ecP: ECPoint, k: BigInteger, paramSet: WeierstrassEllipticCurvesParamSet): ECPoint =
    multiply(ecP, k, paramSet.a, paramSet.b, paramSet.p)

fun multiply(k: BigInteger, paramSet: WeierstrassEllipticCurvesParamSet): ECPoint =
    multiply(paramSet.P, k, paramSet.a, paramSet.b, paramSet.p)

fun multiply(ecP: ECPoint, i: UInt, paramSet: WeierstrassEllipticCurvesParamSet): ECPoint =
    multiply(ecP, BigInteger.fromUInt(i), paramSet)

fun multiply(ecP: ECPoint, k: BigInteger, a: BigInteger, b: BigInteger, p: BigInteger): ECPoint {
    if (k == BigInteger.ZERO) return ECPointZero

    if (ecP == ECPointZero) return ECPointZero

    var tEcp = ecP
    var resP = ecP
    var tk = k - 1
    if (tk < 0) {
        tk += p // считаем что k < p
    }

    while (tk > 0) {
        if (tk % 2 > 0) {
            resP = if (tEcp.x == resP.x || tEcp.y == resP.y)
                double(resP, a, b, p)
            else
                plus(resP, tEcp, a, b, p)
            tk -= 1
        }
        tEcp = double(tEcp, a, b, p)
        tk /= 2
    }
    return resP
}

fun generateRandom(q: BigInteger): BigInteger {
    // Генерация числа k
    // 0 < k < q
    var k: BigInteger
    val qSize = q.toUByteArray().size
    do {
        val kUByteArray = Random.nextUBytes(qSize)
        k = BigInteger.fromUByteArray(kUByteArray, Sign.POSITIVE)
    } while ((k >= q) or k.equals(0))
    return k
}

// Кол-во бит для представления числа
fun BigInteger.bitCount(): Int = numberOfWords * 64

// Проверка точки на принадлежность кривой
fun checkEPointInCurve(paramSet: WeierstrassEllipticCurvesParamSet, p: ECPoint): Boolean =
    checkEPointInCurve(paramSet.a, paramSet.b, paramSet.p, paramSet.q, p)

fun checkEPointInCurve(a: BigInteger, b: BigInteger, p: BigInteger, q: BigInteger, p1: ECPoint): Boolean {
    val yy = (p1.y * p1.y).mod(p)
    val xx = (p1.x * p1.x).mod(p)
    val xxx = (p1.x * xx).mod(p)
    val ax = (a * p1.x).mod(p)
    return yy == (xxx + ax + b).mod(p)
}
