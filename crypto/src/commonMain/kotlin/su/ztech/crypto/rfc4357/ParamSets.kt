/*
 * Created by Stanislav Merzlyakov
 * st.merzlyakov@yandex.ru
 *  in May-2022.
 */

package su.ztech.crypto.rfc4357

import com.ionspin.kotlin.bignum.integer.BigInteger
import su.ztech.crypto.ecurve.ECPoint
import su.ztech.crypto.ecurve.WeierstrassEllipticCurvesParamSet

val GOST_3110_2001_CRYPTOPRO_A_PARAM_SET = WeierstrassEllipticCurvesParamSet(
    p = BigInteger.parseString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97", 16),
    a = BigInteger.parseString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd94", 16),
    b = BigInteger.parseString("a6", 16),
    q = BigInteger.parseString("ffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893", 16),
    m = BigInteger.parseString("ffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893", 16),
    P = ECPoint(
        x = BigInteger.parseString("1", 16),
        y = BigInteger.parseString("8d91e471e0989cda27df505a453f2b7635294f2ddf23e3b122acc99c9e9f1e14", 16)
    )
)

val GOST_3110_2001_CRYPTOPRO_B_PARAM_SET = WeierstrassEllipticCurvesParamSet(
    p = BigInteger.parseString("8000000000000000000000000000000000000000000000000000000000000c99", 16),
    a = BigInteger.parseString("8000000000000000000000000000000000000000000000000000000000000c96", 16),
    b = BigInteger.parseString("3e1af419a269a5f866a7d3c25c3df80ae979259373ff2b182f49d4ce7e1bbc8b", 16),
    q = BigInteger.parseString("800000000000000000000000000000015f700cfff1a624e5e497161bcc8a198f", 16),
    m = BigInteger.parseString("ffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893", 16),
    P = ECPoint(
        x = BigInteger.parseString("1", 16),
        y = BigInteger.parseString("3fa8124359f96680b83d1c3eb2c070e5c545c9858d03ecfb744bf8d717717efc", 16)
    )
)

val GOST_3110_2001_CRYPTOPRO_C_PARAM_SET = WeierstrassEllipticCurvesParamSet(
    p = BigInteger.parseString("9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d759b", 16),
    a = BigInteger.parseString("9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d7598", 16),
    b = BigInteger.parseString("805a", 16),
    q = BigInteger.parseString("9b9f605f5a858107ab1ec85e6b41c8aa582ca3511eddfb74f02f3a6598980bb9", 16),
    m = BigInteger.parseString("ffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893", 16),
    P = ECPoint(
        x = BigInteger.parseString("0", 16),
        y = BigInteger.parseString("41ece55743711a8c3cbf3783cd08c0ee4d4dc440d4641a8f366e550dfdb3bb67", 16)
    )
)
