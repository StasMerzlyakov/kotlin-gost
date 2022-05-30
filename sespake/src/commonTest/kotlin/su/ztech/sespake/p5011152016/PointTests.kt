/*
 * Created by Stanislav Merzlyakov
 * st.merzlyakov@yandex.ru
 *  in May-2022.
 */

package su.ztech.sespake.p5011152016

import com.ionspin.kotlin.bignum.integer.BigInteger
import su.ztech.crypto.OID_GOST_3110_2001_CRYPTOPRO_A_PARAM_SET
import su.ztech.crypto.OID_GOST_3110_2001_CRYPTOPRO_B_PARAM_SET
import su.ztech.crypto.OID_GOST_3110_2001_CRYPTOPRO_C_PARAM_SET
import su.ztech.crypto.OID_GOST_3110_2012_256_PARAM_SET_A
import su.ztech.crypto.OID_GOST_3110_2012_512_PARAM_SET_A
import su.ztech.crypto.OID_GOST_3110_2012_512_PARAM_SET_B
import su.ztech.crypto.OID_GOST_3110_2012_512_PARAM_SET_C
import su.ztech.crypto.ecurve.ECPoint
import su.ztech.crypto.ecurve.WeierstrassEllipticCurvesParamSet
import su.ztech.crypto.ecurve.checkEPointInCurve
import su.ztech.crypto.getGost34102012ParamSet
import su.ztech.sespake.getSespakeEPoints
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * To verify that the dots from the standard text are correctly wrapped in the program
 */
class PointTests {

    @Test
    fun testGost512ParamSetA() {
        val paramSet = getGost34102012ParamSet(OID_GOST_3110_2012_512_PARAM_SET_A)
        val points = getSespakeEPoints(OID_GOST_3110_2012_512_PARAM_SET_A)
        testParamSetAndPoints(paramSet, points)
    }

    @Test
    fun testGost512ParamSetB() {
        val paramSet = getGost34102012ParamSet(OID_GOST_3110_2012_512_PARAM_SET_B)
        val points = getSespakeEPoints(OID_GOST_3110_2012_512_PARAM_SET_B)
        testParamSetAndPoints(paramSet, points)
    }

    @Test
    fun testGost512ParamSetC() {
        val paramSet = getGost34102012ParamSet(OID_GOST_3110_2012_512_PARAM_SET_C)
        val points = getSespakeEPoints(OID_GOST_3110_2012_512_PARAM_SET_C)
        testParamSetAndPoints(paramSet, points)
    }

    @Test
    fun testGost256ParamSetA() {
        val paramSet = getGost34102012ParamSet(OID_GOST_3110_2012_256_PARAM_SET_A)
        val points = getSespakeEPoints(OID_GOST_3110_2012_256_PARAM_SET_A)
        testParamSetAndPoints(paramSet, points)
    }

    @Test
    fun testCryptoProAParamSet() {
        val paramSet = getGost34102012ParamSet(OID_GOST_3110_2001_CRYPTOPRO_A_PARAM_SET)
        val points = getSespakeEPoints(OID_GOST_3110_2001_CRYPTOPRO_A_PARAM_SET)
        testParamSetAndPoints(paramSet, points)
    }

    @Test
    fun testCryptoProBParamSet() {
        val paramSet = getGost34102012ParamSet(OID_GOST_3110_2001_CRYPTOPRO_B_PARAM_SET)
        val points = getSespakeEPoints(OID_GOST_3110_2001_CRYPTOPRO_B_PARAM_SET)
        testParamSetAndPoints(paramSet, points)
    }

    @Test
    fun testCryptoProCParamSet() {
        val paramSet = getGost34102012ParamSet(OID_GOST_3110_2001_CRYPTOPRO_C_PARAM_SET)
        val points = getSespakeEPoints(OID_GOST_3110_2001_CRYPTOPRO_C_PARAM_SET)
        testParamSetAndPoints(paramSet, points)
    }

    private fun testParamSetAndPoints(paramSet: WeierstrassEllipticCurvesParamSet, points: Array<ECPoint>) {
        testEPoint(paramSet.a, paramSet.b, paramSet.p, paramSet.q, paramSet.P)
        points.forEach {
            testEPoint(paramSet.a, paramSet.b, paramSet.p, paramSet.q, it)
        }
    }

    private fun testEPoint(a: BigInteger, b: BigInteger, p: BigInteger, q: BigInteger, it: ECPoint) {
        assertEquals(
            true,
            checkEPointInCurve(a, b, p, q, it)
        )
    }
}
