/*
 * Created by Stanislav Merzlyakov
 * st.merzlyakov@yandex.ru
 *  in May-2022.
 */

package su.ztech.sespake.p5011152016

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import su.ztech.crypto.OID_GOST_3410_2012_256
import su.ztech.crypto.ecurve.ECPoint
import su.ztech.crypto.ecurve.WeierstrassEllipticCurvesParamSet
import su.ztech.crypto.ecurve.checkEPointInCurve
import su.ztech.crypto.ecurve.generateRandom
import su.ztech.crypto.ecurve.minus
import su.ztech.crypto.ecurve.multiply
import su.ztech.crypto.ecurve.plus
import su.ztech.crypto.ecurve.pointToUByteArrayLE
import su.ztech.crypto.getGost34102012ParamSet
import su.ztech.crypto.getGostHash
import su.ztech.crypto.getPbkdf2Len
import su.ztech.crypto.gost34112012.BLOCK_SIZE
import su.ztech.sespake.getSespakeEPoints
import su.ztech.sespake.p5011112016.pbkdf2
import su.ztech.sespake.p5011132016.hmacGostR34112012256

fun int(value: UByteArray): BigInteger {
    return BigInteger.fromUByteArray(value.reversedArray(), Sign.POSITIVE)
}

fun funF(pw: UByteArray, salt: UByteArray, n: Int, len: Int): BigInteger {
    val pbkdf2 = pbkdf2(pw, salt, n, len)
    val fValue = pbkdf2.copyOfRange(0, len / 8)
    return int(fValue)
}

class SideA(
    private val pw: UByteArray,
    private val salt: UByteArray,
    val idA: UByteArray = UByteArray(0),
    private val cLim1: Int = 3,
    cLim2: Int = 20,
    cLim3: Int = 10000,
    val generateAlpha: (BigInteger) -> BigInteger = ::generateRandom // в unit-тестах нужно конкретное значение.
) {
    init {
        if (cLim1 != 3) // в поддерживаемых наборах только по три точки
            throw AssertionError("cLim1 not in {3,...,5}")
        if (cLim2 < 7 || cLim2 > 20)
            throw AssertionError("cLim2 not in {7,...,20}")
        if (cLim3 < 1000 || cLim3 > 10000)
            throw AssertionError("cLim3 not in {10^3,...,10^5}")
    }

    private var c1 = cLim1
    val c1Value: Int
        get() = c1

    private var c2 = cLim2
    val c2Value: Int
        get() = c2

    private var c3 = cLim3
    val c3Value: Int
        get() = c3

    private var paramSetValue: WeierstrassEllipticCurvesParamSet? = null
    private val paramSet: WeierstrassEllipticCurvesParamSet
        get() = paramSetValue!!

    private var qPWValue: ECPoint? = null
    private val qPW: ECPoint
        get() = qPWValue!!

    private var alphaValue: BigInteger? = null
    private val alpha: BigInteger
        get() = alphaValue!!

    private var za = 0
    private var kaValue: UByteArray? = null
    val ka: UByteArray
        get() = kaValue!!

    private var ind: Int = 0
    private var u1: ECPoint? = null
    private var u2: ECPoint? = null
    private var dataA: UByteArray = UByteArray(0)

    private fun checkAttempts() {
        if (c1 == 0 || c2 == 0 || c3 == 0) {
            resetValues()
            throw AssertionError("attempts are exhausted")
        }
    }

    fun step1(
        algOid: String,
        ind: Int = 1,
        qPWVal: ECPoint = generateQPW(algOid, pw, salt, ind)
    ): ECPoint {
        checkAttempts()
        c1--
        c2--
        c3--
        resetValues()

        this.ind = ind
        paramSetValue = getGost34102012ParamSet(algOid)
        qPWValue = qPWVal
        alphaValue = generateAlpha.invoke(paramSet.q)

        za = 0
        u1 = multiply(paramSet.P, alpha, paramSet)
        u1 = minus(u1!!, qPW, paramSet)
        return u1!!
    }

    fun step2(u2: ECPoint, dataA: UByteArray = UByteArray(0)): UByteArray {

        if (u1 == null || kaValue != null) {
            resetValues()
            throw AssertionError("attempts are exhausted")
        }

        this.u2 = u2
        this.dataA = dataA

        if (checkEPointInCurve(paramSet, u2).not()) {
            resetValues()
            throw AssertionError("authentication failed")
        }

        val qa = minus(u2, qPW, paramSet)

        val k = if (paramSet.m != paramSet.q) {
            paramSet.m / paramSet.q
        } else {
            BigInteger.ONE
        }

        val src = pointToUByteArrayLE(multiply(qa, k * alpha, paramSet))

        kaValue = getGostHash(OID_GOST_3410_2012_256, src)

        val toHmac = ubyteArrayOf(0x01u) + idA + ubyteArrayOf(ind.toUByte()) +
            salt + pointToUByteArrayLE(u1!!) + pointToUByteArrayLE(u2) + dataA

        val hmac = hmacGostR34112012256(kaValue!!, toHmac)

        return dataA + hmac
    }

    fun step3(hmacB: UByteArray, idB: UByteArray = UByteArray(0)) {

        if (kaValue == null) {
            resetValues()
            throw AssertionError("attempts are exhausted")
        }

        val dataB = hmacB.copyOfRange(0, hmacB.size - BLOCK_SIZE / 2)
        val hmac = hmacB.copyOfRange(dataB.size, hmacB.size)

        val toHmac = ubyteArrayOf(0x02u) + idB + ubyteArrayOf(ind.toUByte()) +
            salt + pointToUByteArrayLE(u1!!) + pointToUByteArrayLE(u2!!) +
            dataA + dataB

        val hmacForCheck = hmacGostR34112012256(kaValue!!, toHmac)

        if (!hmac.contentEquals(hmacForCheck) or (za == 1)) {
            resetValues()
            throw AssertionError("authentication failed")
        }
        c1 = cLim1
        c2++
    }

    fun resetValues() {
        za = 0
        kaValue = null
        ind = 0
        u1 = null
        u2 = null
        dataA = UByteArray(0)
        paramSetValue = null
        qPWValue = null
        alphaValue = null
    }
}

fun generateQPW(algOid: String, pw: UByteArray, salt: UByteArray, ind: Int = 0): ECPoint {
    val paramSet = getGost34102012ParamSet(algOid)
    val ePoints = getSespakeEPoints(algOid)
    val len = getPbkdf2Len(algOid)
    val fValue = funF(pw, salt, 2000, len)
    return multiply(ePoints[ind - 1], fValue, paramSet)
}

class SideB(
    private val pw: UByteArray,
    private val ind: Int = 1,
    private val salt: UByteArray,
    algOid: String,
    private val cLim1: Int = 3,
    cLim2: Int = 20,
    cLim3: Int = 10000,
    val idB: UByteArray = UByteArray(0),
    private val qPW: ECPoint = generateQPW(algOid, pw, salt, ind),
    val generateBetta: (BigInteger) -> BigInteger = ::generateRandom // в unit-тестах нужно конкретное значение.
) {

    private var paramSet: WeierstrassEllipticCurvesParamSet
    private var kbValue: UByteArray? = null
    val kb: UByteArray
        get() = kbValue!!

    private var zb = 0
    private var u1: ECPoint? = null
    private var u2: ECPoint? = null

    init {
        if (cLim1 != 3) // в поддерживаемых наборах только по три точки
            throw AssertionError("cLim1 not in {3,...,5}")
        if (cLim2 < 7 || cLim2 > 20)
            throw AssertionError("cLim2 not in {7,...,20}")
        if (cLim3 < 1000 || cLim3 > 10000)
            throw AssertionError("cLim3 not in {10^3,...,10^5}")

        if (ind < 1 || ind > cLim1) {
            throw AssertionError("ind value error")
        }
        paramSet = getGost34102012ParamSet(algOid)
    }

    private var c1 = cLim1
    val c1Value: Int
        get() = c1

    private var c2 = cLim2
    val c2Value: Int
        get() = c2

    private var c3 = cLim3
    val c3Value: Int
        get() = c3

    private fun checkAttempts() {
        if (c1 == 0 || c2 == 0 || c3 == 0) {
            throw AssertionError("attempts are exhausted")
        }
    }

    fun step1(u1: ECPoint): ECPoint {
        kbValue = null
        u2 = null
        this.u1 = u1
        checkAttempts()
        c1--
        c2--
        c3--
        with(paramSet) {
            if (checkEPointInCurve(paramSet, u1).not()) {
                resetValues()
                throw AssertionError("authentication failed")
            }

            val betta = generateBetta.invoke(q)
            val bettaP = multiply(P, betta, paramSet)

            u2 = plus(bettaP, qPW, paramSet)

            val qb = plus(u1, qPW, paramSet)

            val k = if (paramSet.m != paramSet.q) {
                paramSet.m / paramSet.q
            } else {
                BigInteger.ONE
            }

            /*var kbetta = (k * betta).mod(q)
            if (kbetta < 0) {
                kbetta += q
            } */

            val src = pointToUByteArrayLE(multiply(qb, k * betta, paramSet))

            //  val src = pointToUByteArrayLE(multiply(qb, betta, paramSet))

            kbValue = getGostHash(OID_GOST_3410_2012_256, src)

            return u2!!
        }
    }

    fun step2(hmacA: UByteArray, idA: UByteArray = UByteArray(0), dataB: UByteArray = UByteArray(0)): UByteArray {
        if (kbValue == null || u2 == null || u1 == null) {
            resetValues()
            throw AssertionError("attempts are exhausted")
        }

        val dataA = hmacA.copyOfRange(0, hmacA.size - BLOCK_SIZE / 2)
        val hmac = hmacA.copyOfRange(dataA.size, hmacA.size)

        val toHmacCheck = ubyteArrayOf(0x01u) + idA + ubyteArrayOf(ind.toUByte()) +
            salt +
            pointToUByteArrayLE(u1!!) + pointToUByteArrayLE(u2!!) + dataA

        val hmacForCheck = hmacGostR34112012256(kbValue!!, toHmacCheck)

        if (!hmac.contentEquals(hmacForCheck) or (zb == 1)) {
            resetValues()
            throw AssertionError("authentication failed")
        }
        c1 = cLim1
        c2++

        val toHmac = ubyteArrayOf(0x02u) + idB + ubyteArrayOf(ind.toUByte()) +
            salt + pointToUByteArrayLE(u1!!) + pointToUByteArrayLE(u2!!) +
            dataA + dataB

        val hmacB = hmacGostR34112012256(kbValue!!, toHmac)
        return dataB + hmacB
    }

    private fun resetValues() {
        kbValue = null
        zb = 0
        u1 = null
        u2 = null
    }
}
