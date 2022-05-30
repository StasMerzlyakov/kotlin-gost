/*
 * Created by Stanislav Merzlyakov
 * st.merzlyakov@yandex.ru
 *  in May-2022.
 */

package su.ztech.crypto.gost34122008

import kotlin.test.Test
import kotlin.test.assertContentEquals

class MagmaTest {

    // A.3.1
    @Test
    fun doTestT() {
        val t = ubyteArrayOf(0xfdu, 0xb9u, 0x75u, 0x31u)
        gostT(t)
        assertContentEquals(
            ubyteArrayOf(0x2au, 0x19u, 0x6fu, 0x34u),
            t
        )
        gostT(t)
        assertContentEquals(
            ubyteArrayOf(0xebu, 0xd9u, 0xf0u, 0x3au),
            t
        )
        gostT(t)
        assertContentEquals(
            ubyteArrayOf(0xb0u, 0x39u, 0xbbu, 0x3du),
            t
        )
        gostT(t)
        assertContentEquals(
            ubyteArrayOf(0x68u, 0x69u, 0x54u, 0x33u),
            t
        )
    }

    // A.3.2
    @Test
    fun doTestg() {
        val key = ubyteArrayOf(0x87u, 0x65u, 0x43u, 0x21u)
        val a = ubyteArrayOf(0xfeu, 0xdcu, 0xbau, 0x98u)

        val a1 = gostg(key, a)
        assertContentEquals(
            ubyteArrayOf(0xfdu, 0xcbu, 0xc2u, 0x0cu),
            a1
        )

        val a2 = gostg(a1, ubyteArrayOf(0x87u, 0x65u, 0x43u, 0x21u))
        assertContentEquals(
            ubyteArrayOf(0x7eu, 0x79u, 0x1au, 0x4bu),
            a2
        )

        val a3 = gostg(a2, ubyteArrayOf(0xfdu, 0xcbu, 0xc2u, 0x0cu))
        assertContentEquals(
            ubyteArrayOf(0xc7u, 0x65u, 0x49u, 0xecu),
            a3
        )

        val a4 = gostg(a3, ubyteArrayOf(0x7eu, 0x79u, 0x1au, 0x4bu))
        assertContentEquals(
            ubyteArrayOf(0x97u, 0x91u, 0xc8u, 0x49u),
            a4
        )
    }

    // A.3.3
    @Test
    fun doTestKey() {
        val keyPair = Pair(
            ubyteArrayOf(
                0xffu, 0xeeu, 0xddu, 0xccu, 0xbbu, 0xaau, 0x99u, 0x88u,
                0x77u, 0x66u, 0x55u, 0x44u, 0x33u, 0x22u, 0x11u, 0x00u
            ),
            ubyteArrayOf(
                0xf0u, 0xf1u, 0xf2u, 0xf3u, 0xf4u, 0xf5u, 0xf6u, 0xf7u,
                0xf8u, 0xf9u, 0xfau, 0xfbu, 0xfcu, 0xfdu, 0xfeu, 0xffu
            )
        )

        val keyMap = createIterationKeys(keyPair)

        assertContentEquals(
            ubyteArrayOf(0xffu, 0xeeu, 0xddu, 0xccu),
            keyMap[1]
        )

        assertContentEquals(
            ubyteArrayOf(0xbbu, 0xaau, 0x99u, 0x88u),
            keyMap[2]
        )

        assertContentEquals(
            ubyteArrayOf(0x77u, 0x66u, 0x55u, 0x44u),
            keyMap[3]
        )

        assertContentEquals(
            ubyteArrayOf(0x33u, 0x22u, 0x11u, 0x00u),
            keyMap[4]
        )

        assertContentEquals(
            ubyteArrayOf(0xf0u, 0xf1u, 0xf2u, 0xf3u),
            keyMap[5]
        )

        assertContentEquals(
            ubyteArrayOf(0xf4u, 0xf5u, 0xf6u, 0xf7u),
            keyMap[6]
        )

        assertContentEquals(
            ubyteArrayOf(0xf8u, 0xf9u, 0xfau, 0xfbu),
            keyMap[7]
        )

        assertContentEquals(
            ubyteArrayOf(0xfcu, 0xfdu, 0xfeu, 0xffu),
            keyMap[8]
        )

        assertContentEquals(
            ubyteArrayOf(0xffu, 0xeeu, 0xddu, 0xccu),
            keyMap[9]
        )

        assertContentEquals(
            ubyteArrayOf(0xbbu, 0xaau, 0x99u, 0x88u),
            keyMap[10]
        )

        assertContentEquals(
            ubyteArrayOf(0x77u, 0x66u, 0x55u, 0x44u),
            keyMap[11]
        )

        assertContentEquals(
            ubyteArrayOf(0x33u, 0x22u, 0x11u, 0x00u),
            keyMap[12]
        )

        assertContentEquals(
            ubyteArrayOf(0xf0u, 0xf1u, 0xf2u, 0xf3u),
            keyMap[13]
        )

        assertContentEquals(
            ubyteArrayOf(0xf4u, 0xf5u, 0xf6u, 0xf7u),
            keyMap[14]
        )

        assertContentEquals(
            ubyteArrayOf(0xf8u, 0xf9u, 0xfau, 0xfbu),
            keyMap[15]
        )

        assertContentEquals(
            ubyteArrayOf(0xfcu, 0xfdu, 0xfeu, 0xffu),
            keyMap[16]
        )

        assertContentEquals(
            ubyteArrayOf(0xffu, 0xeeu, 0xddu, 0xccu),
            keyMap[17]
        )

        assertContentEquals(
            ubyteArrayOf(0xbbu, 0xaau, 0x99u, 0x88u),
            keyMap[18]
        )

        assertContentEquals(
            ubyteArrayOf(0x77u, 0x66u, 0x55u, 0x44u),
            keyMap[19]
        )

        assertContentEquals(
            ubyteArrayOf(0x33u, 0x22u, 0x11u, 0x00u),
            keyMap[20]
        )

        assertContentEquals(
            ubyteArrayOf(0xf0u, 0xf1u, 0xf2u, 0xf3u),
            keyMap[21]
        )

        assertContentEquals(
            ubyteArrayOf(0xf4u, 0xf5u, 0xf6u, 0xf7u),
            keyMap[22]
        )

        assertContentEquals(
            ubyteArrayOf(0xf8u, 0xf9u, 0xfau, 0xfbu),
            keyMap[23]
        )

        assertContentEquals(
            ubyteArrayOf(0xfcu, 0xfdu, 0xfeu, 0xffu),
            keyMap[24]
        )

        assertContentEquals(
            ubyteArrayOf(0xffu, 0xeeu, 0xddu, 0xccu),
            keyMap[32]
        )

        assertContentEquals(
            ubyteArrayOf(0xbbu, 0xaau, 0x99u, 0x88u),
            keyMap[31]
        )

        assertContentEquals(
            ubyteArrayOf(0x77u, 0x66u, 0x55u, 0x44u),
            keyMap[30]
        )

        assertContentEquals(
            ubyteArrayOf(0x33u, 0x22u, 0x11u, 0x00u),
            keyMap[29]
        )

        assertContentEquals(
            ubyteArrayOf(0xf0u, 0xf1u, 0xf2u, 0xf3u),
            keyMap[28]
        )

        assertContentEquals(
            ubyteArrayOf(0xf4u, 0xf5u, 0xf6u, 0xf7u),
            keyMap[27]
        )

        assertContentEquals(
            ubyteArrayOf(0xf8u, 0xf9u, 0xfau, 0xfbu),
            keyMap[26]
        )

        assertContentEquals(
            ubyteArrayOf(0xfcu, 0xfdu, 0xfeu, 0xffu),
            keyMap[25]
        )
    }

    // A.3.4
    @Test
    fun gostMagmaEncrypt() {
        val keyPair = Pair(
            ubyteArrayOf(
                0xffu, 0xeeu, 0xddu, 0xccu, 0xbbu, 0xaau, 0x99u, 0x88u,
                0x77u, 0x66u, 0x55u, 0x44u, 0x33u, 0x22u, 0x11u, 0x00u
            ),
            ubyteArrayOf(
                0xf0u, 0xf1u, 0xf2u, 0xf3u, 0xf4u, 0xf5u, 0xf6u, 0xf7u,
                0xf8u, 0xf9u, 0xfau, 0xfbu, 0xfcu, 0xfdu, 0xfeu, 0xffu
            )
        )
        // keyPair.second.reverse()
        // keyPair.first.reverse()

        val magma = Magma(keyPair) // KeyPair(keyPair.second, keyPair.first))
        val a = ubyteArrayOf(0xfeu, 0xdcu, 0xbau, 0x98u, 0x76u, 0x54u, 0x32u, 0x10u)
        // a.reverse()
        val enc = magma.encrypt(a)
        assertContentEquals(
            ubyteArrayOf(0x4eu, 0xe9u, 0x01u, 0xe5u, 0xc2u, 0xd8u, 0xcau, 0x3du),
            enc
        )

        assertContentEquals(
            a,
            magma.decrypt(enc)
        )
    }
}
