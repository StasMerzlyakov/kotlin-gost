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
import su.ztech.crypto.toUByteArray
import su.ztech.sespake.getSespakeEPoints
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class ProtocolTest {

    @Test
    fun test1() {
        val algOid = OID_GOST_3110_2001_CRYPTOPRO_A_PARAM_SET
        val ind = 1
        val idA = ubyteArrayOf(0u, 0u, 0u, 0u)
        val idB = ubyteArrayOf(0u, 0u, 0u, 0u)
        val pw = "123456".toUByteArray()
        assertContentEquals(
            ubyteArrayOf(0x31u, 0x32u, 0x33u, 0x34u, 0x35u, 0x36u),
            pw
        )

        val salt = ubyteArrayOf(
            0x29u, 0x23u, 0xbeu, 0x84u, 0xe1u, 0x6cu, 0xd6u, 0xaeu,
            0x52u, 0x90u, 0x49u, 0xf1u, 0xf1u, 0xbbu, 0xe9u, 0xebu
        )

        val getTestAlpha: (BigInteger) -> BigInteger = {
            BigInteger.parseString("fccbd45d1f2538097d5a031fa68bbb43c84d12b3de47b7061c0d5e24993e0c87", 16)
        }

        val getTestBetta: (BigInteger) -> BigInteger = {
            BigInteger.parseString("f2144faddc497d9ef6324912fd367840ee509a2032aedb1c0a890d133b45f596", 16)
        }

        val qPW = generateQPW(algOid, pw, salt, ind)
        assertEquals(
            BigInteger.parseString("9d339b3396ae4a816388a14c79ab3a8dd495fa4c53f0d4076579022ef2aaeb68", 16),
            qPW.x
        )
        assertEquals(
            BigInteger.parseString("dad91482e208590fd316bf959480f5ec2c17463ec8fc8f63030649b452cddda8", 16),
            qPW.y
        )

        val sideA = SideA(
            pw = pw,
            salt = salt,
            idA = idA,
            generateAlpha = getTestAlpha
        )

        val sideB = SideB(
            pw = pw,
            ind = ind,
            salt = salt,
            algOid = algOid,
            idB = idB,
            qPW = qPW,
            generateBetta = getTestBetta
        )

        val u1 = sideA.step1(algOid, ind, qPW)

        assertEquals(
            BigInteger.parseString("cf73b30dd577369fb98e2a93d6d98d7450f9ceef2bada1e3dcb8bb1016dff1e1", 16),
            u1.x
        )
        assertEquals(
            BigInteger.parseString("1cf05014caedbdb1635120b30e0a445060b8f1cca52965cf83c4838d554ca4e2", 16),
            u1.y
        )

        val u2 = sideB.step1(u1)
        assertEquals(
            BigInteger.parseString("6e1bfb24b6131a3ad0b60e477a38715c6f96f21bb0b2f9ebd67680e804a77199", 16),
            u2.x
        )
        assertEquals(
            BigInteger.parseString("873ee3c546c41e8f707298f11b955fe64f7577d52d7dadc1beccb9925178ca80", 16),
            u2.y
        )

        val hmac = sideA.step2(u2)

        assertContentEquals(
            ubyteArrayOf(
                0xbdu, 0x35u, 0xc5u, 0x0eu, 0x90u, 0x60u, 0xe6u, 0x4fu,
                0x04u, 0x2eu, 0x7bu, 0xe6u, 0xccu, 0x02u, 0x99u, 0x84u,
                0x0cu, 0x8eu, 0x27u, 0x82u, 0xb8u, 0xe5u, 0x9cu, 0x3du,
                0xd4u, 0x47u, 0x50u, 0x11u, 0x16u, 0x73u, 0xc5u, 0xeau
            ),
            hmac
        )

        val hmac2 = sideB.step2(hmac, idA)

        assertContentEquals(
            ubyteArrayOf(
                0xc8u, 0xc8u, 0x2cu, 0x0fu, 0xedu, 0x8eu, 0x4du, 0x1eu,
                0x41u, 0x42u, 0xd7u, 0xa9u, 0xf0u, 0x55u, 0xb4u, 0x5fu,
                0xf6u, 0x71u, 0x2du, 0x2fu, 0x41u, 0xbfu, 0x26u, 0xefu,
                0x2fu, 0xbcu, 0x37u, 0xc5u, 0x56u, 0x4bu, 0x86u, 0xd3u
            ),
            hmac2
        )

        sideA.step3(hmac2, idB)
    }

    @Test
    fun test2() {
        // Кривая id-GostR3410-2001-CryptoPro-B-ParamSet
        val algOid = OID_GOST_3110_2001_CRYPTOPRO_B_PARAM_SET
        val ind = 1
        val idA = ubyteArrayOf(0u, 0u, 0u, 0u)
        val idB = ubyteArrayOf(0u, 0u, 0u, 0u)
        val pw = "123456".toUByteArray()

        val salt = ubyteArrayOf(
            0x29u, 0x23u, 0xbeu, 0x84u, 0xe1u, 0x6cu, 0xd6u, 0xaeu,
            0x52u, 0x90u, 0x49u, 0xf1u, 0xf1u, 0xbbu, 0xe9u, 0xebu
        )

        val ePoint = getSespakeEPoints(algOid)[ind - 1]
        assertEquals(
            BigInteger.parseString("0ad754474a915d9d706c6b8dc879858a1cb85cc8f6c148fc3120825393ecd394", 16),
            ePoint.x
        )
        assertEquals(
            BigInteger.parseString("68c33b6d0343cf72cb19666ffd487fa94294dc677b28c8e27ec36068ff85ed83", 16),
            ePoint.y
        )

        val qPW = generateQPW(algOid, pw, salt, ind)
        assertEquals(
            BigInteger.parseString("7a7211a430fd4e31b815e6d2454eea9574f034c5c442dce1723d69555d3ee4c9", 16),
            qPW.x
        )
        assertEquals(
            BigInteger.parseString("2995e857187808e80d3e40a00fb87128e203f2d91c1f15d8193a5aad95964734", 16),
            qPW.y
        )

        val getTestAlpha: (BigInteger) -> BigInteger = {
            BigInteger.parseString("499d72b90299cab0da1f8be19d9122f622a13b32b730c46bd0664044f2144fad", 16)
        }

        val getTestBetta: (BigInteger) -> BigInteger = {
            BigInteger.parseString("0f69ff614957ef83668edc2d7ed614be76f7b253db23c5cc9c52bf7df8f4669d", 16)
        }

        val sideA = SideA(
            pw = pw,
            salt = salt,
            idA = idA,
            generateAlpha = getTestAlpha
        )

        val sideB = SideB(
            pw = pw,
            ind = ind,
            salt = salt,
            algOid = algOid,
            idB = idB,
            qPW = qPW,
            generateBetta = getTestBetta
        )

        val u1 = sideA.step1(algOid, ind, qPW)

        assertEquals(
            BigInteger.parseString("35e78fcbc24998eb3039445a9de7032aadf291e7768196ef618e45bed80edf88", 16),
            u1.x
        )
        assertEquals(
            BigInteger.parseString("1970a4697295f6d361d2c3edd3885794c1254bac3f4adb4a3346ad01a911d13c", 16),
            u1.y
        )

        val u2 = sideB.step1(u1)

        assertContentEquals(
            ubyteArrayOf(
                0xa6u, 0x26u, 0xdeu, 0x01u, 0xb1u, 0x68u, 0x0fu, 0xf7u, 0x51u, 0x30u, 0x09u, 0x12u, 0x2bu, 0xceu, 0xe1u, 0x89u,
                0x68u, 0x83u, 0x39u, 0x4fu, 0x96u, 0x03u, 0x01u, 0x72u, 0x45u, 0x5cu, 0x9au, 0xe0u, 0x60u, 0xccu, 0xe4u, 0x4au
            ),
            sideB.kb
        )

        assertEquals(
            BigInteger.parseString("20d7a92b238143e3f137be904d52fa35c45a29f02a7226a7ac83a1172c2a55cd", 16),
            u2.x
        )
        assertEquals(
            BigInteger.parseString("5fc4cd6ffb0e76ea8603ce9e6dab5164285617969ab3bfab09fbeb8595d1f47b", 16),
            u2.y
        )

        val hmacA = sideA.step2(u2)

        assertContentEquals(
            ubyteArrayOf(
                0xa6u, 0x26u, 0xdeu, 0x01u, 0xb1u, 0x68u, 0x0fu, 0xf7u, 0x51u, 0x30u, 0x09u, 0x12u, 0x2bu, 0xceu, 0xe1u, 0x89u,
                0x68u, 0x83u, 0x39u, 0x4fu, 0x96u, 0x03u, 0x01u, 0x72u, 0x45u, 0x5cu, 0x9au, 0xe0u, 0x60u, 0xccu, 0xe4u, 0x4au
            ),
            sideA.ka
        )

        assertContentEquals(
            ubyteArrayOf(
                0x55u, 0x7au, 0x59u, 0x61u, 0x42u, 0x60u, 0x39u, 0xa1u, 0x52u, 0xc8u, 0x23u, 0xa7u, 0x65u, 0x04u, 0x59u, 0xb0u,
                0x62u, 0xbeu, 0x3du, 0x47u, 0x56u, 0x53u, 0x03u, 0x09u, 0x95u, 0x57u, 0x1cu, 0xe7u, 0x53u, 0x40u, 0x26u, 0x47u
            ),
            hmacA
        )

        val hmacB = sideB.step2(hmacA, idA)

        assertContentEquals(
            ubyteArrayOf(
                0x3bu, 0xc5u, 0x5eu, 0x27u, 0x07u, 0x84u, 0x19u, 0x94u, 0xc4u, 0xb9u, 0xcau, 0xbau, 0x43u, 0xe6u, 0xceu, 0x6au,
                0x09u, 0x2du, 0xe9u, 0x08u, 0x83u, 0x76u, 0x5fu, 0xb6u, 0xc3u, 0x44u, 0xc6u, 0x1du, 0x76u, 0x02u, 0x96u, 0xe9u
            ),
            hmacB
        )

        sideA.step3(hmacB, idB)
    }

    @Test
    fun test3() {
        val algOid = OID_GOST_3110_2001_CRYPTOPRO_C_PARAM_SET
        val ind = 1
        val idA = ubyteArrayOf(0u, 0u, 0u, 0u)
        val idB = ubyteArrayOf(0u, 0u, 0u, 0u)
        val pw = "123456".toUByteArray()

        val salt = ubyteArrayOf(
            0x29u, 0x23u, 0xbeu, 0x84u, 0xe1u, 0x6cu, 0xd6u, 0xaeu,
            0x52u, 0x90u, 0x49u, 0xf1u, 0xf1u, 0xbbu, 0xe9u, 0xebu
        )

        val ePoint = getSespakeEPoints(algOid)[ind - 1]
        assertEquals(
            BigInteger.parseString("339f791f62938871f241c1c89643619aa8b2c7d7706ce69be01fddff3f840003", 16),
            ePoint.x
        )
        assertEquals(
            BigInteger.parseString("31d6d9264cc6f8fe09bf7aa48910b4ad5ddfd74a2ef4699b76de09ffed295f11", 16),
            ePoint.y
        )

        val qPW = generateQPW(algOid, pw, salt, ind)
        assertEquals(
            BigInteger.parseString("8b666917d42c455331358c50c3c12c85b898a2e454b50dd773541da02e1c3068", 16),
            qPW.x
        )
        assertEquals(
            BigInteger.parseString("8a9b6c4703934b7f0dc903f52c16275e1d38b568117c7cff3bd322a99a311fe9", 16),
            qPW.y
        )

        val getTestAlpha: (BigInteger) -> BigInteger = {
            BigInteger.parseString("3a54ac3f19ad9d0b1eac8acdcea70e581f1dac33d13feafd81e762378639c1a8", 16)
        }

        val getTestBetta: (BigInteger) -> BigInteger = {
            BigInteger.parseString("448781782bf7c0e52a1dd9e6758fd3482d90d3cfccf42232cf357e59a4d49fd4", 16)
        }

        val sideA = SideA(
            pw = pw,
            salt = salt,
            idA = idA,
            generateAlpha = getTestAlpha
        )

        val sideB = SideB(
            pw = pw,
            ind = ind,
            salt = salt,
            algOid = algOid,
            idB = idB,
            qPW = qPW,
            generateBetta = getTestBetta
        )

        val u1 = sideA.step1(algOid, ind, qPW)

        assertEquals(
            BigInteger.parseString("2124a22e00b1be2114f5ca42d58d55a0a9f2b08f8cb10275eddf8243402abb7a", 16),
            u1.x
        )
        assertEquals(
            BigInteger.parseString("62497815861d15877b7ad2e86768a2deb0f755a8b1a8897fc5235da783914a59", 16),
            u1.y
        )

        val u2 = sideB.step1(u1)

        assertContentEquals(
            ubyteArrayOf(
                0xbeu, 0x7eu, 0x7eu, 0x47u, 0xb4u, 0x11u, 0x16u, 0xf2u, 0xc7u, 0x7eu, 0x3bu, 0x8fu, 0xceu, 0x40u, 0x30u, 0x72u,
                0xcau, 0x82u, 0x45u, 0x0du, 0x65u, 0xdeu, 0xfcu, 0x71u, 0xa9u, 0x56u, 0x49u, 0xe4u, 0xdeu, 0xeau, 0xecu, 0xeeu
            ),
            sideB.kb
        )

        assertEquals(
            BigInteger.parseString("47ad0110d1620fe38832e90b58971d2e0b9183dd52de23422b6fc47bec64541a", 16),
            u2.x
        )
        assertEquals(
            BigInteger.parseString("8296af496b3c52640e738a195d63ab7bfb457aba7c71b5649cc3e300829cbf0a", 16),
            u2.y
        )

        val hmacA = sideA.step2(u2)

        assertContentEquals(
            ubyteArrayOf(
                0xbeu, 0x7eu, 0x7eu, 0x47u, 0xb4u, 0x11u, 0x16u, 0xf2u, 0xc7u, 0x7eu, 0x3bu, 0x8fu, 0xceu, 0x40u, 0x30u, 0x72u,
                0xcau, 0x82u, 0x45u, 0x0du, 0x65u, 0xdeu, 0xfcu, 0x71u, 0xa9u, 0x56u, 0x49u, 0xe4u, 0xdeu, 0xeau, 0xecu, 0xeeu
            ),
            sideA.ka
        )

        assertContentEquals(
            ubyteArrayOf(
                0x47u, 0x58u, 0xfau, 0x64u, 0x9fu, 0x2eu, 0x31u, 0x3bu, 0xf2u, 0x70u, 0x8bu, 0x76u, 0xa7u, 0xf7u, 0xa7u, 0x5au,
                0x37u, 0xceu, 0x9eu, 0x7fu, 0x55u, 0xc3u, 0xfcu, 0x5au, 0x55u, 0x77u, 0xe8u, 0x77u, 0xa7u, 0xa2u, 0xc1u, 0xeau
            ),
            hmacA
        )

        val hmacB = sideB.step2(hmacA, idA)

        assertContentEquals(
            ubyteArrayOf(
                0x2fu, 0x33u, 0xb9u, 0xbfu, 0xf0u, 0x7du, 0xcdu, 0xe3u, 0x44u, 0x67u, 0xbdu, 0xb0u, 0x7fu, 0x62u, 0xfcu, 0xa8u,
                0xb3u, 0x52u, 0x3au, 0x64u, 0x39u, 0xefu, 0xf1u, 0xc9u, 0x93u, 0xbau, 0x0bu, 0x4cu, 0xe6u, 0xc2u, 0xedu, 0xe4u
            ),
            hmacB
        )

        sideA.step3(hmacB, idB)
    }

    @Test
    fun test4() {
        val algOid = OID_GOST_3110_2012_512_PARAM_SET_A
        val ind = 1
        val idA = ubyteArrayOf(0u, 0u, 0u, 0u)
        val idB = ubyteArrayOf(0u, 0u, 0u, 0u)
        val pw = "123456".toUByteArray()

        val salt = ubyteArrayOf(
            0x29u, 0x23u, 0xbeu, 0x84u, 0xe1u, 0x6cu, 0xd6u, 0xaeu,
            0x52u, 0x90u, 0x49u, 0xf1u, 0xf1u, 0xbbu, 0xe9u, 0xebu
        )

        val ePoint = getSespakeEPoints(algOid)[ind - 1]
        assertEquals(
            BigInteger.parseString(
                "301aac1a3b3e9c8a65bc095b541ce1d23728b93818e8b61f963e5d5b13eec0fe" +
                    "e6b06f8cd481a07bb647b649232e5179b019eef7296a3d9cfa2b66ee8bf0cbf2",
                16
            ),
            ePoint.x
        )
        assertEquals(
            BigInteger.parseString(
                "191177dd41ce19cc849c3938abf3adaab366e5eb2d22a972b2dcc69283523e89" +
                    "c9907f1d89ab9d96f473f96815da6e0a47297fcdd8b3adac37d4886f7ad055e0",
                16
            ),
            ePoint.y
        )

        val qPW = generateQPW(algOid, pw, salt, ind)
        assertEquals(
            BigInteger.parseString(
                "a8b54a6339b296f5c5227670fb1482010b4b07e3642974b40c58a5f1da33370e" +
                    "fed546eb17c6a707f3fc69671deba10a6de03a55f859473e9074a89b4a7b5488",
                16
            ),
            qPW.x
        )
        assertEquals(
            BigInteger.parseString(
                "febf437ecf21536328b32f4c8e0430d5c0c096001c08a378ac30b8634412f44c" +
                    "5ba9b7096642f51cc3a018cd1599c849cd62917a370eca3bbc6bed5eedabdd77",
                16
            ),
            qPW.y
        )

        val getTestAlpha: (BigInteger) -> BigInteger = {
            BigInteger.parseString(
                "3ce54325db52fe798824aead11bb16fa766857d04a4af7d468672f16d90e7396" +
                    "046a46f815693e85b1ce5464da9270181f82333b0715057bbe8d61d400505f0e",
                16
            )
        }

        val getTestBetta: (BigInteger) -> BigInteger = {
            BigInteger.parseString(
                "b5c286a79aa8e97ec0e19bc1959a1d15f12f8c97870ba9d68cc12811a56a3bb1" +
                    "1440610825796a49d468cdc9c2d02d76598a27973d5960c5f50bce28d8d345f4",
                16
            )
        }

        val sideA = SideA(
            pw = pw,
            salt = salt,
            idA = idA,
            generateAlpha = getTestAlpha
        )

        val sideB = SideB(
            pw = pw,
            ind = ind,
            salt = salt,
            algOid = algOid,
            idB = idB,
            qPW = qPW,
            generateBetta = getTestBetta
        )

        val u1 = sideA.step1(algOid, ind, qPW)

        assertEquals(
            BigInteger.parseString(
                "e8732d5471901b3eb9a31aaebeac7a6155c2c8fc1c960cb475e14074987dd2c8" +
                    "4eccafac0835735a5c2df3d1c8dacf4a1d2e38e1e4419f5df4e25b7f8dd90b50",
                16
            ),
            u1.x
        )
        assertEquals(
            BigInteger.parseString(
                "d680a41eaec979d49f4752008e9e92eb0efc1950d74b85e852be47f3958d5500" +
                    "0442d859e5b459de5dc7acaa0c36383cd1f98f271333c6083dcecaf07ac825b8",
                16
            ),
            u1.y
        )

        val u2 = sideB.step1(u1)

        assertContentEquals(
            ubyteArrayOf(
                0x53u, 0x24u, 0xdeu, 0xf8u, 0x48u, 0xb6u, 0x63u, 0xccu, 0x26u, 0x42u, 0x2fu, 0x5eu, 0x45u, 0xeeu, 0xc3u, 0x4cu,
                0x51u, 0xd2u, 0x43u, 0x61u, 0xb1u, 0x65u, 0x60u, 0xcau, 0x58u, 0xa3u, 0xd3u, 0x28u, 0x45u, 0x86u, 0xcbu, 0x7au
            ),
            sideB.kb
        )

        assertEquals(
            BigInteger.parseString(
                "1830804bf1fb07ebd43f27d03ff71ad9c7c31becaf1d3585dfb9e356c36638dc" +
                    "d82aba559dec06d46c862566653dfe0b116eb1a68439b0283f4d79ce48408eee",
                16
            ),
            u2.x
        )
        assertEquals(
            BigInteger.parseString(
                "23b33ae97fba92e06095c41525aedf7b5d96fe9ca8e0244ed6c8a565d542d05e" +
                    "d3044cafb1a8ac9a570c5133ba846d61da77f54da2daf13b0def7d90a0796f06",
                16
            ),
            u2.y
        )

        val hmacA = sideA.step2(u2)

        assertContentEquals(
            ubyteArrayOf(
                0x53u, 0x24u, 0xdeu, 0xf8u, 0x48u, 0xb6u, 0x63u, 0xccu, 0x26u, 0x42u, 0x2fu, 0x5eu, 0x45u, 0xeeu, 0xc3u, 0x4cu,
                0x51u, 0xd2u, 0x43u, 0x61u, 0xb1u, 0x65u, 0x60u, 0xcau, 0x58u, 0xa3u, 0xd3u, 0x28u, 0x45u, 0x86u, 0xcbu, 0x7au
            ),
            sideA.ka
        )

        assertContentEquals(
            ubyteArrayOf(
                0x37u, 0xe6u, 0x1au, 0x43u, 0x2du, 0x85u, 0x75u, 0x9bu, 0x30u, 0x13u, 0xa2u, 0x9du, 0xd6u, 0x82u, 0xf1u, 0x4du,
                0x33u, 0xcau, 0x86u, 0x89u, 0x37u, 0xdbu, 0x4bu, 0xf2u, 0x02u, 0x91u, 0xedu, 0xcfu, 0x6bu, 0xe2u, 0x4bu, 0x4eu
            ),
            hmacA
        )

        val hmacB = sideB.step2(hmacA, idA)

        assertContentEquals(
            ubyteArrayOf(
                0x72u, 0xdcu, 0xdeu, 0x19u, 0x5fu, 0x26u, 0x4bu, 0xb8u, 0xa8u, 0x1du, 0x2au, 0xfeu, 0x2fu, 0xd9u, 0xdau, 0x2du,
                0x60u, 0x12u, 0x81u, 0x9cu, 0x15u, 0xf7u, 0x11u, 0xdbu, 0x2bu, 0xc4u, 0xc5u, 0x74u, 0x85u, 0x9eu, 0x05u, 0x3eu
            ),
            hmacB
        )

        sideA.step3(hmacB, idB)
    }

    @Test
    fun test5() {
        val algOid = OID_GOST_3110_2012_512_PARAM_SET_B
        val ind = 1
        val idA = ubyteArrayOf(0u, 0u, 0u, 0u)
        val idB = ubyteArrayOf(0u, 0u, 0u, 0u)
        val pw = "123456".toUByteArray()

        val salt = ubyteArrayOf(
            0x29u, 0x23u, 0xbeu, 0x84u, 0xe1u, 0x6cu, 0xd6u, 0xaeu,
            0x52u, 0x90u, 0x49u, 0xf1u, 0xf1u, 0xbbu, 0xe9u, 0xebu
        )

        val ePoint = getSespakeEPoints(algOid)[ind - 1]
        assertEquals(
            BigInteger.parseString(
                "488cf12b403e539fde9ee32fc36b6ed52aad9ec34ff478c259159a85e99d3dda" +
                    "dfd5d73606ecee351e0f780a14c3e9f14e985d9d7ddec93b064fc89b0c843650",
                16
            ),
            ePoint.x
        )
        assertEquals(
            BigInteger.parseString(
                "7bc73c032edc5f2c74dd7d9da12e1856a061ce344a77253f620592752b1f3a3d" +
                    "cbbc87eb27ec4ed5e236dfeb03f3972404747e277671e53a9e412e82aaf6c3f7",
                16
            ),
            ePoint.y
        )

        val qPW = generateQPW(algOid, pw, salt, ind)

        assertEquals(
            BigInteger.parseString(
                "2383039092052ed0e8ca3f751c11ebb891b8f32f7c66a437dec86345c63efc4b" +
                    "a1ecd04dfc11826dd581cbc1d744754e284c00b04eef9cd6eff22c12432c46fd",
                16
            ),
            qPW.x
        )
        assertEquals(
            BigInteger.parseString(
                "374202580afbaf2f68da8a5c03ab82e71eb4c1f1fdd881aa2911d0206d470039" +
                    "275d298d5477901565ab826ec4492f67eebcf3194442f272fd2cad9a5f04234f",
                16
            ),
            qPW.y
        )

        val getTestAlpha: (BigInteger) -> BigInteger = {
            BigInteger.parseString(
                "715e893fa639bf341296e0623e6d29dadf26b163c278767a7982a989462a3863" +
                    "fe12aef8bd403d59c4dc4720570d4163db0805c7c10c4e818f9cb785b04b9997",
                16
            )
        }

        val getTestBetta: (BigInteger) -> BigInteger = {
            BigInteger.parseString(
                "30fa8c2b4146c2dbbe82bed04d7378877e8c06753bd0a0ff71ebf2befe8da8f3" +
                    "dc0836468e2ce7c5c961281b6505140f8407413f03c2cb1d201ea1286ce30e6d",
                16
            )
        }

        val sideA = SideA(
            pw = pw,
            salt = salt,
            idA = idA,
            generateAlpha = getTestAlpha
        )

        val sideB = SideB(
            pw = pw,
            ind = ind,
            salt = salt,
            algOid = algOid,
            idB = idB,
            qPW = qPW,
            generateBetta = getTestBetta
        )

        val u1 = sideA.step1(algOid, ind, qPW)

        assertEquals(
            BigInteger.parseString(
                "0ab9e56fc0d48e4982ee0a0b09507a63dc530181611d9f00d0464724415757b9" +
                    "de1c647178783a0fb4648dfd8e3da1efeb4db29de4711c8599191054ca7de6c4",
                16
            ),
            u1.x
        )
        assertEquals(
            BigInteger.parseString(
                "4decae941f8d19c44daae9eb132019e116478124e76430b8bee16ce6910a06c8" +
                    "a2fed68f4907e4ba17c4f4e3356dc3b3b8647165b9c1aae54b1c13239bfa8213",
                16
            ),
            u1.y
        )

        val u2 = sideB.step1(u1)

        assertContentEquals(
            ubyteArrayOf(
                0xd5u, 0x90u, 0xe0u, 0x5eu, 0xf5u, 0xaeu, 0xceu, 0x8bu, 0x7cu, 0xfbu, 0xfcu, 0x71u, 0xbeu, 0x45u, 0x5fu, 0x29u,
                0xa5u, 0xccu, 0x66u, 0x6fu, 0x85u, 0xcdu, 0xb1u, 0x7eu, 0x7cu, 0xc7u, 0x16u, 0xc5u, 0x9fu, 0xf1u, 0x70u, 0xe9u,
            ),
            sideB.kb
        )

        assertEquals(
            BigInteger.parseString(
                "66defd2a42f0efe38ed3d4a4dfbed6b86d40f4adf156c86fee1605dbf6b057b1" +
                    "2fe82a0be4823f7f215b5110673e02e3bf44f0ae26630005fcfd9f01473127eb",
                16
            ),
            u2.x
        )
        assertEquals(
            BigInteger.parseString(
                "36168c6d20c9514556ab442bf63ded0115346916ef45af7e5517f59205d1cc52" +
                    "ae2e72c3036f13cab7de12932e4a3acd0789f5e2474ff722b81334676c8a3371",
                16
            ),
            u2.y
        )

        val hmacA = sideA.step2(u2)

        assertContentEquals(
            ubyteArrayOf(
                0xd5u, 0x90u, 0xe0u, 0x5eu, 0xf5u, 0xaeu, 0xceu, 0x8bu, 0x7cu, 0xfbu, 0xfcu, 0x71u, 0xbeu, 0x45u, 0x5fu, 0x29u,
                0xa5u, 0xccu, 0x66u, 0x6fu, 0x85u, 0xcdu, 0xb1u, 0x7eu, 0x7cu, 0xc7u, 0x16u, 0xc5u, 0x9fu, 0xf1u, 0x70u, 0xe9u,
            ),
            sideA.ka
        )

        assertContentEquals(
            ubyteArrayOf(
                0x9eu, 0xc1u, 0xa8u, 0x74u, 0x93u, 0xb2u, 0x87u, 0xc9u, 0xcau, 0xc3u, 0xdau, 0xc2u, 0xa2u, 0xd7u, 0x1bu, 0x82u,
                0x8du, 0xc5u, 0x97u, 0x7cu, 0xb0u, 0x03u, 0x93u, 0x42u, 0xc1u, 0x5au, 0xcdu, 0xfbu, 0x66u, 0xc8u, 0xcfu, 0x89u,
            ),
            hmacA
        )

        val hmacB = sideB.step2(hmacA, idA)

        assertContentEquals(
            ubyteArrayOf(
                0xa9u, 0xb2u, 0xf1u, 0x9bu, 0xd9u, 0xc1u, 0xfdu, 0x0fu, 0x0cu, 0xabu, 0xfdu, 0x09u, 0x52u, 0x94u, 0xc6u, 0xe6u,
                0x3cu, 0xd5u, 0x9fu, 0x12u, 0xcfu, 0x8eu, 0xfdu, 0x01u, 0x12u, 0x46u, 0x0du, 0xb7u, 0xaau, 0x20u, 0xbbu, 0x6eu,
            ),
            hmacB
        )

        sideA.step3(hmacB, idB)
    }

    @Test
    fun test6() {
        val algOid = OID_GOST_3110_2012_256_PARAM_SET_A
        val ind = 1
        val idA = ubyteArrayOf(0u, 0u, 0u, 0u)
        val idB = ubyteArrayOf(0u, 0u, 0u, 0u)
        val pw = "123456".toUByteArray()

        val salt = ubyteArrayOf(
            0x29u, 0x23u, 0xbeu, 0x84u, 0xe1u, 0x6cu, 0xd6u, 0xaeu,
            0x52u, 0x90u, 0x49u, 0xf1u, 0xf1u, 0xbbu, 0xe9u, 0xebu
        )

        val ePoint = getSespakeEPoints(algOid)[ind - 1]
        assertEquals(
            BigInteger.parseString(
                "5161b08a973d521bdde0cbd45b68aa0470e1058dd936e5bd618fd3373770eed9", 16
            ),
            ePoint.x
        )
        assertEquals(
            BigInteger.parseString(
                "c1633db551677c62b9c2b69d47e503c0f8ca83b6b3109dece0a5f985d77a83a7", 16
            ),
            ePoint.y
        )

        val qPW = generateQPW(algOid, pw, salt, ind)

        assertEquals(
            BigInteger.parseString(
                "a0fd0bcfaa07f640c802aa95f42e80b28bb758fbcb7ee2aca2cc0a615b567207", 16
            ),
            qPW.x
        )
        assertEquals(
            BigInteger.parseString(
                "52cf0c960f362894bd097d198999e965bd940c7828e0d2ad38a0097f68135047", 16
            ),
            qPW.y
        )

        val getTestAlpha: (BigInteger) -> BigInteger = {
            BigInteger.parseString(
                "147b72f6684fb8fd1b418a899f7dbecaf5fce60b13685baa95328654a7f0707f", 16
            )
        }

        val getTestBetta: (BigInteger) -> BigInteger = {
            BigInteger.parseString(
                "30d5cfadaa0e31b405e6734c03ec4c5df0f02f4ba25c9a3b320ee6453567b4cb", 16
            )
        }

        val sideA = SideA(
            pw = pw,
            salt = salt,
            idA = idA,
            generateAlpha = getTestAlpha
        )

        val sideB = SideB(
            pw = pw,
            ind = ind,
            salt = salt,
            algOid = algOid,
            idB = idB,
            qPW = qPW,
            generateBetta = getTestBetta
        )

        val u1 = sideA.step1(algOid, ind, qPW)

        assertEquals(
            BigInteger.parseString(
                "8e8929226c7f679ea8c2dfb833d1f8062d62a9672493df02ad7462014c0edbc6", 16
            ),
            u1.x
        )
        assertEquals(
            BigInteger.parseString(
                "20f2382c2425aaa638f61e8b70fcf70dae6bcb2f9f341b33ae577c62395aa816", 16
            ),
            u1.y
        )

        val u2 = sideB.step1(u1)

        assertContentEquals(
            ubyteArrayOf(
                0x7du, 0xf7u, 0x1au, 0xc3u, 0x27u, 0xedu, 0x51u, 0x7du, 0x0du, 0xe4u, 0x03u, 0xe8u, 0x17u, 0xc6u, 0x20u, 0x4bu,
                0xc1u, 0x91u, 0x65u, 0xb9u, 0xd1u, 0x00u, 0x2bu, 0x9fu, 0x10u, 0x88u, 0xa6u, 0xcdu, 0xa6u, 0xeau, 0xcfu, 0x27u,
            ),
            sideB.kb
        )

        assertEquals(
            BigInteger.parseString(
                "47182ed8f018fa93a5d837e52724af6051c168ef15e4a40fe926473bc3f1032a", 16
            ),
            u2.x
        )
        assertEquals(
            BigInteger.parseString(
                "97f3e1e674da53b0ec3ebb1a62a25c7424f4334950daec4d33045f78d9faeeb4", 16
            ),
            u2.y
        )

        val hmacA = sideA.step2(u2)

        assertContentEquals(
            ubyteArrayOf(
                0x7du, 0xf7u, 0x1au, 0xc3u, 0x27u, 0xedu, 0x51u, 0x7du, 0x0du, 0xe4u, 0x03u, 0xe8u, 0x17u, 0xc6u, 0x20u, 0x4bu,
                0xc1u, 0x91u, 0x65u, 0xb9u, 0xd1u, 0x00u, 0x2bu, 0x9fu, 0x10u, 0x88u, 0xa6u, 0xcdu, 0xa6u, 0xeau, 0xcfu, 0x27u,
            ),
            sideA.ka
        )

        assertContentEquals(
            ubyteArrayOf(
                0xf5u, 0x69u, 0xf6u, 0xe7u, 0x68u, 0x9eu, 0xf0u, 0xbau, 0x08u, 0x46u, 0x98u, 0xccu, 0x0eu, 0xbcu, 0xacu, 0x59u,
                0x67u, 0x8cu, 0x93u, 0x26u, 0xafu, 0x21u, 0xf5u, 0x4du, 0x3eu, 0x90u, 0x05u, 0x29u, 0x32u, 0x6bu, 0x41u, 0xeeu
            ),
            hmacA
        )

        val hmacB = sideB.step2(hmacA, idA)

        assertContentEquals(
            ubyteArrayOf(
                0x80u, 0xd5u, 0xf0u, 0x3bu, 0x48u, 0x22u, 0x37u, 0x76u, 0x43u, 0xb4u, 0xffu, 0x92u, 0x05u, 0xddu, 0xedu, 0xb1u,
                0x9fu, 0x22u, 0x80u, 0x1fu, 0xb4u, 0xdeu, 0x0bu, 0xfbu, 0xe0u, 0x74u, 0x55u, 0xc2u, 0x54u, 0x32u, 0x45u, 0x1eu
            ),
            hmacB
        )

        sideA.step3(hmacB, idB)
    }

    @Test
    fun test7() {
        val algOid = OID_GOST_3110_2012_512_PARAM_SET_C
        val ind = 1
        val idA = ubyteArrayOf(0u, 0u, 0u, 0u)
        val idB = ubyteArrayOf(0u, 0u, 0u, 0u)
        val pw = "123456".toUByteArray()

        val salt = ubyteArrayOf(
            0x29u, 0x23u, 0xbeu, 0x84u, 0xe1u, 0x6cu, 0xd6u, 0xaeu,
            0x52u, 0x90u, 0x49u, 0xf1u, 0xf1u, 0xbbu, 0xe9u, 0xebu
        )

        val ePoint = getSespakeEPoints(algOid)[ind - 1]
        assertEquals(
            BigInteger.parseString(
                "5b065ead2e94de0ee2e462de204c93c6b2bf3498ad920393cb60259e1a8ffc7c" +
                    "7e7d4defa20ff4282abf70207e4611d532f40db6800e29d2b53f6ac0713e5b38",
                16
            ),
            ePoint.x
        )
        assertEquals(
            BigInteger.parseString(
                "a39a28c59ff7f796b85223b8834384907c626086415487288ed1182ca4487dc1" +
                    "ae5f37af90fd267b7c0dc8542ea52cd984af54731bc84271d6186d973c91359b",
                16
            ),
            ePoint.y
        )

        val qPW = generateQPW(algOid, pw, salt, ind)

        assertEquals(
            BigInteger.parseString(
                "463e9d38239ddac18e7cc7f6caa7244ae5c49d58dcdfd6a56510d7779496744d" +
                    "75e3e0d5795d4e603f7baea8d24ada989d4179e1db33d1912602fc59470192df",
                16
            ),
            qPW.x
        )
        assertEquals(
            BigInteger.parseString(
                "088874b12c160930aa840f046ee75fa86206f19ca5f431d81e2381d6d947b7b0" +
                    "30577e40f09b1c16f8e6ef84daddba028f8b6e397a27ece0e13197662659af4d",
                16
            ),
            qPW.y
        )

        val getTestAlpha: (BigInteger) -> BigInteger = {
            BigInteger.parseString(
                "0b3fe942126aefc0287f82c6290505aeb117aa8dcb033cee56222dd1b9f9e1e5" +
                    "377583ba300211ec2c399546b4f54578ee925c238d52530c159c7034ccfa0ddd",
                16
            )
        }

        val getTestBetta: (BigInteger) -> BigInteger = {
            BigInteger.parseString(
                "0d494d54fb777781d1324ed6088bb0d9d86b8b0a252aa6a3ee70af8ef44b87a6" +
                    "4cea3a432b61a699bad2d9760d700c2891b6285be0b0bb90f16a40a9b2e0e36a",
                16
            )
        }

        val sideA = SideA(
            pw = pw,
            salt = salt,
            idA = idA,
            generateAlpha = getTestAlpha
        )

        val sideB = SideB(
            pw = pw,
            ind = ind,
            salt = salt,
            algOid = algOid,
            idB = idB,
            qPW = qPW,
            generateBetta = getTestBetta
        )

        val u1 = sideA.step1(algOid, ind, qPW)

        assertEquals(
            BigInteger.parseString(
                "03664ef83e51beaec1f11711f8742b180001c7734a715e4a693758acd9851b38" +
                    "C6d7e0a316d809b75694ae1b356951a93c91a9b85aa3e3a561742211fd238852",
                16
            ),
            u1.x
        )
        assertEquals(
            BigInteger.parseString(
                "2b92fa93fab060fa86c3039eb2904bc18cbe45032dc3c93ce1c6ba1542a29e0d" +
                    "790a5f7b63928ed9e50d1fefd6bd00ade4eb021bc62a560567a3419e74dfc08a",
                16
            ),
            u1.y
        )

        val u2 = sideB.step1(u1)

        assertContentEquals(
            ubyteArrayOf(
                0x84u, 0x14u, 0xe1u, 0x12u, 0x6cu, 0x56u, 0xa1u, 0x1eu, 0x1fu, 0x5eu, 0xa0u, 0xb7u, 0xc3u, 0xbdu, 0xabu, 0xe9u,
                0x8bu, 0x26u, 0x8bu, 0x59u, 0xd4u, 0x08u, 0xf9u, 0x7cu, 0xd0u, 0xeau, 0xd7u, 0xc2u, 0x7eu, 0xe4u, 0x9cu, 0x15u
            ),
            sideB.kb
        )

        assertEquals(
            BigInteger.parseString(
                "32260df3ddeabaa9c5c1f55248e8e9a3552cefb81a19f0ac1e10f3b7280a844c" +
                    "5362b527da1c6ec7eeace2a77aa1167f5e18a4bb6bc6445b4f479ca239245002",
                16
            ),
            u2.x
        )
        assertEquals(
            BigInteger.parseString(
                "04e0612a0c8cd4323535899d0698dd09bb9fc4302016f1b236c86692358ffd98" +
                    "1cd082c0129763bd4749ee5bb014255d1de0fd7775deccb564213ebc7100001d",
                16
            ),
            u2.y
        )

        val hmacA = sideA.step2(u2)

        assertContentEquals(
            ubyteArrayOf(
                0x84u, 0x14u, 0xe1u, 0x12u, 0x6cu, 0x56u, 0xa1u, 0x1eu, 0x1fu, 0x5eu, 0xa0u, 0xb7u, 0xc3u, 0xbdu, 0xabu, 0xe9u,
                0x8bu, 0x26u, 0x8bu, 0x59u, 0xd4u, 0x08u, 0xf9u, 0x7cu, 0xd0u, 0xeau, 0xd7u, 0xc2u, 0x7eu, 0xe4u, 0x9cu, 0x15u
            ),
            sideA.ka
        )

        assertContentEquals(
            ubyteArrayOf(
                0x53u, 0x0bu, 0x77u, 0x63u, 0xc5u, 0x9eu, 0x7cu, 0x98u, 0x52u, 0x59u, 0xadu, 0xebu, 0xafu, 0xa4u, 0x16u, 0x41u,
                0xc6u, 0xf4u, 0x35u, 0x47u, 0x85u, 0x01u, 0xbdu, 0xc9u, 0x7eu, 0xa9u, 0xcfu, 0x88u, 0xa6u, 0x9au, 0x12u, 0x8cu
            ),
            hmacA
        )

        val hmacB = sideB.step2(hmacA, idA)

        assertContentEquals(
            ubyteArrayOf(
                0x3fu, 0x48u, 0x65u, 0xb8u, 0x8cu, 0x81u, 0xe5u, 0xacu, 0x56u, 0x1eu, 0x31u, 0xc1u, 0xb3u, 0xd1u, 0xd9u, 0x0cu,
                0x57u, 0xe1u, 0xe7u, 0x4bu, 0xacu, 0x77u, 0xb1u, 0x63u, 0xacu, 0x60u, 0x74u, 0x82u, 0x4eu, 0x99u, 0xd3u, 0xccu
            ),
            hmacB
        )

        sideA.step3(hmacB, idB)
    }
}
