/*
 * Created by Stanislav Merzlyakov
 * st.merzlyakov@yandex.ru
 *  in May-2022.
 */

package su.ztech.sespake.p5011132016

class PrfTlsGost34112012256(secret: UByteArray, label: UByteArray, seed: UByteArray) {
    private val p256 = P256(secret, label + seed)
    fun next(): UByteArray = p256.next()
}

class PrfTlsGost34112012512(secret: UByteArray, label: UByteArray, seed: UByteArray) {
    private val p512 = P512(secret, label + seed)
    fun next(): UByteArray = p512.next()
}

class PrfIPSecKeyMatGost34112012256(key: UByteArray, s: UByteArray) {
    private val psec256 = PSec256(key, s)
    fun next(): UByteArray = psec256.next()
}

class PrfIPSecKeyMatGost34112012512(key: UByteArray, s: UByteArray) {
    private val psec512 = PSec512(key, s)
    fun next(): UByteArray = psec512.next()
}

class PrfIPSecPrfPlusGost34112012256(key: UByteArray, s: UByteArray) {
    private val pi256 = PSecIter256(key, s)
    fun next(): UByteArray = pi256.next()
}

class PrfIPSecPrfPlusGost34112012512(key: UByteArray, s: UByteArray) {
    private val pi512 = PSecIter512(key, s)
    fun next(): UByteArray = pi512.next()
}

private class P256(secret: UByteArray, s: UByteArray) : P(secret, s, { a: UByteArray, b: UByteArray ->
    hmacGostR34112012256(a, b)
})

private class PSec256(secret: UByteArray, s: UByteArray) : PSec(secret, s, { a: UByteArray, b: UByteArray ->
    hmacGostR34112012256(a, b)
})

private class PSec512(secret: UByteArray, s: UByteArray) : PSec(secret, s, { a: UByteArray, b: UByteArray ->
    hmacGostR34112012512(a, b)
})

private class PSecIter256(secret: UByteArray, s: UByteArray) : PSecIter(secret, s, { a: UByteArray, b: UByteArray ->
    hmacGostR34112012256(a, b)
})

private class P512(secret: UByteArray, s: UByteArray) : P(secret, s, { a: UByteArray, b: UByteArray ->
    hmacGostR34112012512(a, b)
})

private class PSecIter512(secret: UByteArray, s: UByteArray) : PSecIter(secret, s, { a: UByteArray, b: UByteArray ->
    hmacGostR34112012512(a, b)
})

private open class P(private val secret: UByteArray, private val s: UByteArray, private val hmacFn: (UByteArray, UByteArray) -> UByteArray) {
    private var a = s
    fun next(): UByteArray {
        a = hmacFn(secret, a)
        return hmacFn(secret, a + s)
    }
}

private open class PSec(private val secret: UByteArray, private val s: UByteArray, private val hmacFn: (UByteArray, UByteArray) -> UByteArray) {
    private var t = hmacFn(secret, s)
    fun next(): UByteArray {
        val result = t
        t = hmacFn(secret, t + s)
        return result
    }
}

private open class PSecIter(private val secret: UByteArray, private val s: UByteArray, private val hmacFn: (UByteArray, UByteArray) -> UByteArray) {
    private var i: UByte = 0x01u
    private var t = hmacFn(secret, s + ubyteArrayOf(i))

    fun next(): UByteArray {
        val result = t
        i++
        t = hmacFn(secret, t + s + ubyteArrayOf(i))
        return result
    }
}
