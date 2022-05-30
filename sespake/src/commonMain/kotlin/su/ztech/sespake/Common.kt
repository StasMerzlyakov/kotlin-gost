/*
 * Created by Stanislav Merzlyakov
 * st.merzlyakov@yandex.ru
 *  in May-2022.
 */

package su.ztech.sespake

import su.ztech.crypto.OID_GOST_3110_2001_CRYPTOPRO_A_PARAM_SET
import su.ztech.crypto.OID_GOST_3110_2001_CRYPTOPRO_A_PARAM_SET_NAME
import su.ztech.crypto.OID_GOST_3110_2001_CRYPTOPRO_B_PARAM_SET
import su.ztech.crypto.OID_GOST_3110_2001_CRYPTOPRO_B_PARAM_SET_NAME
import su.ztech.crypto.OID_GOST_3110_2001_CRYPTOPRO_C_PARAM_SET
import su.ztech.crypto.OID_GOST_3110_2001_CRYPTOPRO_C_PARAM_SET_NAME
import su.ztech.crypto.OID_GOST_3110_2012_256_PARAM_SET_A
import su.ztech.crypto.OID_GOST_3110_2012_256_PARAM_SET_A_NAME
import su.ztech.crypto.OID_GOST_3110_2012_512_PARAM_SET_A
import su.ztech.crypto.OID_GOST_3110_2012_512_PARAM_SET_A_NAME
import su.ztech.crypto.OID_GOST_3110_2012_512_PARAM_SET_B
import su.ztech.crypto.OID_GOST_3110_2012_512_PARAM_SET_B_NAME
import su.ztech.crypto.OID_GOST_3110_2012_512_PARAM_SET_C
import su.ztech.crypto.OID_GOST_3110_2012_512_PARAM_SET_C_NAME
import su.ztech.crypto.ecurve.ECPoint
import su.ztech.sespake.p5011152016.CryptoProAQ1
import su.ztech.sespake.p5011152016.CryptoProAQ2
import su.ztech.sespake.p5011152016.CryptoProAQ3
import su.ztech.sespake.p5011152016.CryptoProBQ1
import su.ztech.sespake.p5011152016.CryptoProBQ2
import su.ztech.sespake.p5011152016.CryptoProBQ3
import su.ztech.sespake.p5011152016.CryptoProCQ1
import su.ztech.sespake.p5011152016.CryptoProCQ2
import su.ztech.sespake.p5011152016.CryptoProCQ3
import su.ztech.sespake.p5011152016.Gost256EPointA1
import su.ztech.sespake.p5011152016.Gost256EPointA2
import su.ztech.sespake.p5011152016.Gost256EPointA3
import su.ztech.sespake.p5011152016.Gost512EPointA1
import su.ztech.sespake.p5011152016.Gost512EPointA2
import su.ztech.sespake.p5011152016.Gost512EPointA3
import su.ztech.sespake.p5011152016.Gost512EPointB1
import su.ztech.sespake.p5011152016.Gost512EPointB2
import su.ztech.sespake.p5011152016.Gost512EPointB3
import su.ztech.sespake.p5011152016.Gost512EPointC1
import su.ztech.sespake.p5011152016.Gost512EPointC2
import su.ztech.sespake.p5011152016.Gost512EPointC3

fun getSespakeEPoints(oidOrName: String): Array<ECPoint> =
    when (oidOrName) {
        OID_GOST_3110_2012_512_PARAM_SET_A, OID_GOST_3110_2012_512_PARAM_SET_A_NAME ->
            arrayOf(Gost512EPointA1, Gost512EPointA2, Gost512EPointA3)
        OID_GOST_3110_2012_512_PARAM_SET_B, OID_GOST_3110_2012_512_PARAM_SET_B_NAME ->
            arrayOf(Gost512EPointB1, Gost512EPointB2, Gost512EPointB3)
        OID_GOST_3110_2012_512_PARAM_SET_C, OID_GOST_3110_2012_512_PARAM_SET_C_NAME ->
            arrayOf(Gost512EPointC1, Gost512EPointC2, Gost512EPointC3)
        OID_GOST_3110_2012_256_PARAM_SET_A, OID_GOST_3110_2012_256_PARAM_SET_A_NAME ->
            arrayOf(Gost256EPointA1, Gost256EPointA2, Gost256EPointA3)
        OID_GOST_3110_2001_CRYPTOPRO_A_PARAM_SET, OID_GOST_3110_2001_CRYPTOPRO_A_PARAM_SET_NAME ->
            arrayOf(CryptoProAQ1, CryptoProAQ2, CryptoProAQ3)
        OID_GOST_3110_2001_CRYPTOPRO_B_PARAM_SET, OID_GOST_3110_2001_CRYPTOPRO_B_PARAM_SET_NAME ->
            arrayOf(CryptoProBQ1, CryptoProBQ2, CryptoProBQ3)
        OID_GOST_3110_2001_CRYPTOPRO_C_PARAM_SET, OID_GOST_3110_2001_CRYPTOPRO_C_PARAM_SET_NAME ->
            arrayOf(CryptoProCQ1, CryptoProCQ2, CryptoProCQ3)
        else -> throw AssertionError("unsupported algorithm id $oidOrName")
    }
