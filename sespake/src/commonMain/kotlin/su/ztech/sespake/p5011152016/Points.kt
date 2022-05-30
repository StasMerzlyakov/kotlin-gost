/*
 * Created by Stanislav Merzlyakov
 * st.merzlyakov@yandex.ru
 *  in May-2022.
 */

package su.ztech.sespake.p5011152016

import com.ionspin.kotlin.bignum.integer.BigInteger
import su.ztech.crypto.ecurve.ECPoint

val CryptoProAQ1 = ECPoint(
    x = BigInteger.parseString(
        "a33ce065b0c23e1d3d026a206f8a1f8747ed1cd92a665bf85198cdb10ac90a5c",
        16
    ),
    y = BigInteger.parseString(
        "b00d0dc0733883f05de9f55fd711f55998f5508cc40bead80c913b4d5b533667",
        16
    ),
)

val CryptoProAQ2 = ECPoint(
    x = BigInteger.parseString(
        "4ce9c2bcf17212b9efcab65c3c815c0ff96d7461c957634dbfd1fe7c9a324d27",
        16
    ),
    y = BigInteger.parseString(
        "f7500d7adea2c2b4a16d838a8faa02b46639eb881f124d0f2506efca0e24289d",
        16
    ),
)

val CryptoProAQ3 = ECPoint(
    x = BigInteger.parseString(
        "31fb8e5070b1e0f52f047f40477c38c6020fd8da9f685791f9237cc47bd89324",
        16
    ),
    y = BigInteger.parseString(
        "8ba1184a4e296dc5c5873639747339ecc71b7fa44d31cc8e35b6615a4f797dd7",
        16
    ),
)

val CryptoProBQ1 = ECPoint(
    x = BigInteger.parseString(
        "0ad754474a915d9d706c6b8dc879858a1cb85cc8f6c148fc3120825393ecd394",
        16
    ),
    y = BigInteger.parseString(
        "68c33b6d0343cf72cb19666ffd487fa94294dc677b28c8e27ec36068ff85ed83",
        16
    ),
)

val CryptoProBQ2 = ECPoint(
    x = BigInteger.parseString(
        "1cd96e72fdf1ce6b544dec12d0d7bcb9f6ba65bba3d9f7af732bcb133c1b6437",
        16
    ),
    y = BigInteger.parseString(
        "34ab5b63c286a2b885ca443ac875a8f9ec0c2f148f1622bc64c83b80e6e3d31f",
        16
    ),
)

val CryptoProBQ3 = ECPoint(
    x = BigInteger.parseString(
        "18dda7154e5abef001dc9943554439cb44b9e26256def176849da5f09b5f690d",
        16
    ),
    y = BigInteger.parseString(
        "3ef584be59673d1751b2fd6e3fdc619e3d756c0d355595b3a62196de048ece44",
        16
    ),
)

val CryptoProCQ1 = ECPoint(
    x = BigInteger.parseString(
        "339f791f62938871f241c1c89643619aa8b2c7d7706ce69be01fddff3f840003",
        16
    ),
    y = BigInteger.parseString(
        "31d6d9264cc6f8fe09bf7aa48910b4ad5ddfd74a2ef4699b76de09ffed295f11",
        16
    ),
)

val CryptoProCQ2 = ECPoint(
    x = BigInteger.parseString(
        "80f4d03b00b1b9b53f6bb4ffa52be65a6d316de846e27f44ccd795bc62d89e23",
        16
    ),
    y = BigInteger.parseString(
        "38dd712518ddec19b46afccccba97338d89d1292427dc12985d4e848066cd1ab",
        16
    ),
)

val CryptoProCQ3 = ECPoint(
    x = BigInteger.parseString(
        "0c8b64c3f0ec7ece81b6232db2e8054666d051ee28254d4b9a4bcb1460ca546b",
        16
    ),
    y = BigInteger.parseString(
        "88c98b48b22b90d0d3a018da55ca0d05cedd82b6c838bd62aba2b823ce82b28f",
        16
    ),
)

val Gost512EPointA1 = ECPoint(
    x = BigInteger.parseString(
        "301aac1a3b3e9c8a65bc095b541ce1d23728b93818e8b61f963e5d5b13eec0fee6" +
            "b06f8cd481a07bb647b649232e5179b019eef7296a3d9cfa2b66ee8bf0cbf2",
        16
    ),
    y = BigInteger.parseString(
        "191177dd41ce19cc849c3938abf3adaab366e5eb2d22a972b2dcc69283523e89" +
            "c9907f1d89ab9d96f473f96815da6e0a47297fcdd8b3adac37d4886f7ad055e0",
        16
    ),
)

val Gost512EPointA2 = ECPoint(
    x = BigInteger.parseString(
        "7edc38f17f88e3105bafb67c419d58fe6a9094dd4dc1a83bcaccc61f020ac447" +
            "92eba888457c658ee2d82557b7c6ab6efd61ba0c3327741d09a561a8b860a085",
        16
    ),
    y = BigInteger.parseString(
        "3af1400a7a469058d9ba75e65ea5d3f4d0bdb357fa57eb73fa4900e2dca4da78" +
            "b8e5ff35ca70e522610bb1fc76b102c81cc4729f94b12822584f6b6229a57ea1",
        16
    ),
)

val Gost512EPointA3 = ECPoint(
    x = BigInteger.parseString(
        "387acfba7bbc5815407474a7c1132a1bded12497243d73ef8133d9810eb21716" +
            "95dde2ff15597e159464a1db207b4d1ff98fbb989f80c2db13bc8ff5fea16d59",
        16
    ),
    y = BigInteger.parseString(
        "4c816d1ca3e145ac448478fb79a77e1ad2dfc69576685e2f6867ec93fbad8aa4" +
            "4111acd104036317095bce467e98f295436199c8ead57f243860d1bde8d88b68",
        16
    ),
)

val Gost512EPointB1 = ECPoint(
    x = BigInteger.parseString(
        "488cf12b403e539fde9ee32fc36b6ed52aad9ec34ff478c259159a85e99d3dda" +
            "dfd5d73606ecee351e0f780a14c3e9f14e985d9d7ddec93b064fc89b0c843650",
        16
    ),
    y = BigInteger.parseString(
        "7bc73c032edc5f2c74dd7d9da12e1856a061ce344a77253f620592752b1f3a3d" +
            "Cbbc87eb27ec4ed5e236dfeb03f3972404747e277671e53a9e412e82aaf6c3f7",
        16
    ),
)

val Gost512EPointB2 = ECPoint(
    x = BigInteger.parseString(
        "175166b97248bda12ec035df2e312a2771d0b16977c9cbc79461ff05e01f719c" +
            "92ae8b53f3b7e3edcacffcc5063b5e9c8de18d0cb87da358350992132173df69",
        16
    ),
    y = BigInteger.parseString(
        "10e2943dc1a18a841ab76ac756fa974948d5a18d071d458a4769c2494fe2a6c5" +
            "966e3c8931e624d87259156aea9317157502698e4a4a489c327b89277cf59b4c",
        16
    ),
)

val Gost512EPointB3 = ECPoint(
    x = BigInteger.parseString(
        "01f4583db894cdebd7c591af848783ee011a20567751ca1561f398a6118ace08" +
            "a4efe1501bda67f39d060270ba660526dc53063c6b40fa5548c9a9e7688f2239",
        16
    ),
    y = BigInteger.parseString(
        "7bc640641d70c8296bd9257c9eebb5b1bd3196a169bac04f7579bf27b5847d4e" +
            "7b4f63748ad81b5469070ed35ad93e5a5258652306f84094eae04a91954536ee",
        16
    ),
)

val Gost256EPointA1 = ECPoint(
    x = BigInteger.parseString(
        "5161b08a973d521bdde0cbd45b68aa0470e1058dd936e5bd618fd3373770eed9",
        16
    ),
    y = BigInteger.parseString(
        "c1633db551677c62b9c2b69d47e503c0f8ca83b6b3109dece0a5f985d77a83a7",
        16
    ),
)

val Gost256EPointA2 = ECPoint(
    x = BigInteger.parseString(
        "d47abd59dccad35849dec9dc721ffa1e44419ca8686406a9f441e61294b210ed",
        16
    ),
    y = BigInteger.parseString(
        "a78b64220bf3375d08de0ea5e2920cfd8f204da6757bf1878ac870fb7e5ca0e8",
        16
    ),
)

val Gost256EPointA3 = ECPoint(
    x = BigInteger.parseString(
        "e0d610ff42ce21eb308980964ca368963fbe5cb08c277187d22d0c94f4bf0762",
        16
    ),
    y = BigInteger.parseString(
        "82619b88da25b666e07b617ff487be8afd5af8b092568b493ecef44ee0c04b5f",
        16
    ),
)

val Gost512EPointC1 = ECPoint(
    x = BigInteger.parseString(
        "5b065ead2e94de0ee2e462de204c93c6b2bf3498ad920393cb60259e1a8ffc7c" +
            "7e7d4defa20ff4282abf70207e4611d532f40db6800e29d2b53f6ac0713e5b38",
        16
    ),
    y = BigInteger.parseString(
        "a39a28c59ff7f796b85223b8834384907c626086415487288ed1182ca4487dc1" +
            "ae5f37af90fd267b7c0dc8542ea52cd984af54731bc84271d6186d973c91359b",
        16
    ),
)

val Gost512EPointC2 = ECPoint(
    x = BigInteger.parseString(
        "b3e6c475f173af4494dd02ad7c9df3bd6a5ca82c3d65ad86fbb330dfb1c40e34" +
            "c4cd04d93f609cff2daea5907d0e08192a29be3ff27522223b868e8bcc6a7b74",
        16
    ),
    y = BigInteger.parseString(
        "53ffcf818281bcf383d9b6542b3b1fcee5bd20cd1c805ed1dacb83ba161167a5" +
            "eb96df52c1d290496043ea514c465ecb37970fcd7ffbb6ca35a767cd0227fe8c",
        16
    ),
)

val Gost512EPointC3 = ECPoint(
    x = BigInteger.parseString(
        "be963ad90f84ff9ff6ff7ddd39d91cea649e849bf20b8cc1e72040cf689a974f" +
            "40f24e10c737bfa558b514c605b7c156e24251b859202b12ef311b0f363171eb",
        16
    ),
    y = BigInteger.parseString(
        "007cfa56f5ae239694e74f7996e1f44fcd4f62205a555fdb627e4212576b4591" +
            "7f88667bcd924a3271f40dc4bbd2f2e216b4fcf59c25fdd8154241d40f42e2ad",
        16
    ),
)
