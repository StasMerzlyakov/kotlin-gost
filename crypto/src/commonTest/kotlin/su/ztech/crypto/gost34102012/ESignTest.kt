/*
 * Created by Stanislav Merzlyakov
 * st.merzlyakov@yandex.ru
 *  in May-2022.
 */

package su.ztech.crypto.gost34102012

import com.ionspin.kotlin.bignum.integer.BigInteger
import su.ztech.crypto.ecurve.ECPoint
import su.ztech.crypto.ecurve.WeierstrassEllipticCurvesParamSet
import su.ztech.crypto.ecurve.bitCount
import su.ztech.crypto.ecurve.multiply
import su.ztech.crypto.ecurve.plus
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ESignTest {

    /**
     * A.1
     */
    @Test
    fun doTest1() {
        val p = BigInteger.parseString("57896044618658097711785492504343953926634992332820282019728792003956564821041")
        assertEquals(BigInteger.parseString("8000000000000000000000000000000000000000000000000000000000000431", 16), p)

        val a = BigInteger.fromInt(7)
        val b = BigInteger.parseString("43308876546767276905765904595650931995942111794451039583252968842033849580414")
        assertEquals(BigInteger.parseString("5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E", 16), b)

        val m = BigInteger.parseString("57896044618658097711785492504343953927082934583725450622380973592137631069619")
        assertEquals(BigInteger.parseString("8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3", 16), m)

        val q = BigInteger.parseString("57896044618658097711785492504343953927082934583725450622380973592137631069619")
        assertEquals(BigInteger.parseString("8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3", 16), q)

        val xp = BigInteger.fromInt(2)
        val yp = BigInteger.parseString("4018974056539037503335449422937059775635739389905545080690979365213431566280")
        assertEquals(BigInteger.parseString("8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8", 16), yp)

        val d = BigInteger.parseString("55441196065363246126355624130324183196576709222340016572108097750006097525544")
        assertEquals(BigInteger.parseString("7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28", 16), d)

        val e = BigInteger.parseString("20798893674476452017134061561508270130637142515379653289952617252661468872421")
        assertEquals(BigInteger.parseString("2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5", 16), e)

        val k = BigInteger.parseString("53854137677348463731403841147996619241504003434302020712960838528893196233395")
        assertEquals(BigInteger.parseString("77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3", 16), k)

        val pointP = ECPoint(xp, yp)
        val c = multiply(pointP, k, a, b, p)

        val xc = BigInteger.parseString("29700980915817952874371204983938256990422752107994319651632687982059210933395")
        assertEquals(BigInteger.parseString("41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493", 16), xc)
        assertEquals(xc, c.x)

        val yc = BigInteger.parseString("32842535278684663477094665322517084506804721032454543268132854556539274060910")
        assertEquals(BigInteger.parseString("489C375A9941A3049E33B34361DD204172AD98C3E5916DE27695D22A61FAE46E", 16), yc)

        assertEquals(yc, c.y)

        val r = BigInteger.parseString("29700980915817952874371204983938256990422752107994319651632687982059210933395")
        assertEquals(BigInteger.parseString("41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493", 16), r)

        assertEquals(r, xc % q)

        // s = ((r * d) + (k * e)) % q
        val s = BigInteger.parseString("574973400270084654178925310019147038455227042649098563933718999175515839552")
        assertEquals(BigInteger.parseString("1456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40", 16), s)

        assertEquals(
            BigInteger.parseString(
                "16466579062874751514215774781156549082208350505243214086709930958760756554" +
                    "86805114828237355116732326045698514758017047279283260786891387213636860095141880"
            ),
            r * d
        )

        assertEquals(
            BigInteger.parseString(
                "11201064834817869279241019273397531870534153261472794992430760061968576919" +
                    "47781645499074398776856220986468884427048944745329774945546130472182474994699295"
            ),
            k * e
        )

        assertEquals(
            BigInteger.parseString(
                "276676438976926207934567940545540809527425037667160090791406910207293334743" +
                    "4586760327311753893588547032167399185065992024613035732437517685819335089841175"
            ),
            r * d + k * e
        )

        assertEquals(s, (r * d + k * e) % q)

        val len = q.bitCount() / 4
        val rVector = r.toString(16).padStart(len, '0')
        val sVector = s.toString(16).padStart(len, '0')
        val eSign = "$rVector$sVector"

        val rVectorStr = eSign.substring(0, len)
        val sVectorStr = eSign.substring(len, 2 * len)

        assertEquals(rVector, rVectorStr)
        assertEquals(sVector, sVectorStr)

        val rCh = BigInteger.parseString(rVectorStr, 16)
        val sCh = BigInteger.parseString(sVectorStr, 16)

        assertEquals(r, rCh)
        assertEquals(s, sCh)

        // v = e.modInverse(q)
        val v = BigInteger.parseString("17686683605934468677301713824900268562746883080675496715288036572431145718978")
        assertEquals(BigInteger.parseString("271A4EE429F84EBC423E388964555BB29D3BA53C7BF945E5FAC8F381706354C2", 16), v)

        assertEquals(v, e.modInverse(q))

        // z1 = (s * v) % q
        val z1 = BigInteger.parseString("37699167500901938556841057293512656108841345190491942619304532412743720999759")
        assertEquals(BigInteger.parseString("5358F8FFB38F7C09ABC782A2DF2A3927DA4077D07205F763682F3A76C9019B4F", 16), z1)

        assertEquals(z1, (sCh * v) % q)

        val z2 = BigInteger.parseString("1417199842734347211251591796950076576924665583897286211449993265333367109221")
        assertEquals(BigInteger.parseString("3221B4FBBF6D101074EC14AFAC2D4F7EFAC4CF9FEC1ED11BAE336D27D527665", 16), z2)

        assertEquals(z2, q - (rCh * v) % q)

        val xq = BigInteger.parseString("57520216126176808443631405023338071176630104906313632182896741342206604859403")
        assertEquals(BigInteger.parseString("7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B", 16), xq)

        val yq = BigInteger.parseString("17614944419213781543809391949654080031942662045363639260709847859438286763994")
        assertEquals(BigInteger.parseString("26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA", 16), yq)

        val pointQ = ECPoint(xq, yq)

        val pointA = multiply(pointP, z1, a, b, p)
        val pointB = multiply(pointQ, z2, a, b, p)
        val pointC = plus(pointA, pointB, a, b, p)

        val cxExpected = BigInteger.parseString("29700980915817952874371204983938256990422752107994319651632687982059210933395")
        assertEquals(BigInteger.parseString("41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493", 16), cxExpected)
        assertEquals(cxExpected, pointC.x)

        val cyExpected = BigInteger.parseString("32842535278684663477094665322517084506804721032454543268132854556539274060910")
        assertEquals(BigInteger.parseString("489C375A9941A3049E33B34361DD204172AD98C3E5916DE27695D22A61FAE46E", 16), cyExpected)

        assertEquals(cyExpected, pointC.y)

        val rS = pointC.x % q

        assertEquals(rCh, rS)
    }

    /**
     * A.2
     */
    @Test
    fun doTest2() {
        val p = BigInteger.parseString(
            "36239861022290036359077887536838743060213209255346786050865461504508561666240" +
                "02482588482022271496854025090823603058735163734263822371964987228582907372403"
        )

        assertEquals(
            BigInteger.parseString(
                "4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DF1D8527" +
                    "41AF4704A0458047E80E4546D35B8336FAC224DD81664BBF528BE6373",
                16
            ),
            p
        )

        val a = BigInteger.fromInt(7)
        val b = BigInteger.parseString(
            "151865506921082853450895003471404315492874752774020643619401882335280998244379373282" +
                "9756914785974674866041605397883677596626326413990136959047435811826396"
        )
        assertEquals(
            BigInteger.parseString(
                "1CFF0806A31116DA29D8CFA54E57EB748BC5F377E49400FDD788B649ECA1AC436183401" +
                    "3B2AD7322480A89CA58E0CF74BC9E540C2ADD6897FAD0A3084F302ADC",
                16
            ),
            b
        )

        val m = BigInteger.parseString(
            "3623986102229003635907788753683874306021320925534678605086546150450856166623969164898305" +
                "032863068499961404079437936585455865192212970734808812618120619743"
        )
        assertEquals(
            BigInteger.parseString(
                "4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DA82F2" +
                    "D7ECB1DBAC719905C5EECC423F1D86E25EDBE23C595D644AAF187E6E6DF",
                16
            ),
            m
        )

        val q = BigInteger.parseString(
            "36239861022290036359077887536838743060213209255346786050865461504508561666239691648983" +
                "05032863068499961404079437936585455865192212970734808812618120619743"
        )
        assertEquals(
            BigInteger.parseString(
                "4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DA82" +
                    "F2D7ECB1DBAC719905C5EECC423F1D86E25EDBE23C595D644AAF187E6E6DF",
                16
            ),
            q
        )

        val xp = BigInteger.parseString(
            "19283569440670228493993094012431375989977866354595079743570754913077665926858354410655" +
                "57681003184874819658004903212332884252335830250729527632383493573274"
        )
        assertEquals(
            BigInteger.parseString(
                "24D19CC64572EE30F396BF6EBBFD7A6C5213B3B3D7057CC825F91093A68CD762" +
                    "FD60611262CD838DC6B60AA7EEE804E28BC849977FAC33B4B530F1B120248A9A",
                16
            ),
            xp
        )

        val yp = BigInteger.parseString(
            "228872869337197285997001215552947841635356232732950618031449742593110286030157281414" +
                "1997072271708807066593850650334152381857347798885864807605098724013854"
        )
        assertEquals(
            BigInteger.parseString(
                "2BB312A43BD2CE6E0D020613C857ACDDCFBF061E91E5F2C3F32447C259F39B2" +
                    "C83AB156D77F1496BF7EB3351E1EE4E43DC1A18B91B24640B6DBB92CB1ADD371E",
                16
            ),
            yp
        )

        val pointP = ECPoint(xp, yp)

        val d = BigInteger.parseString(
            "6100818041363730982195381532398475830068455190695315629823881353548906063017822" +
                "55383608393423372379057665527595116827307025046458837440766121180466875860"
        )

        assertEquals(
            BigInteger.parseString(
                "BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508B102072E8123B2200A" +
                    "0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4",
                16
            ),
            d
        )

        val xq = BigInteger.parseString(
            "9095468530025365965566907686698303100069292725465562815963729653703124985631823" +
                "20436892870052842808608262832456858223580713780290717986855863433431150561"
        )
        assertEquals(
            BigInteger.parseString(
                "115DC5BC96760C7B48598D8AB9E740D4C4A85A65BE33C1815B5C320C854621DD5A515856D13314" +
                    "AF69BC5B924C8B4DDFF75C45415C1D9DD9DD33612CD530EFE1",
                16
            ),
            xq
        )

        val yq = BigInteger.parseString(
            "29214572033744256206324497342484154556407008235594887051648958375095391342973273973802" +
                "87741428246088626609329139441895016863758984106326600572476822372076"
        )
        assertEquals(
            BigInteger.parseString(
                "37C7C90CD40B0F5621DC3AC1B751CFA0E2634FA0503B3D52639F5D7FB72AFD61EA199441D943" +
                    "FFE7F0C70A2759A3CDB84C114E1F9339FDF27F35ECA93677BEEC",
                16
            ),
            yq
        )

        val pointQ = ECPoint(xq, yq)

        val e = BigInteger.parseString(
            "2897963881682868575562827278553865049173745197871825199562947" +
                "4190413889509705366611095534999542487330887197488445389646412816544" +
                "63513296973827706272045964"
        )
        assertEquals(
            BigInteger.parseString(
                "3754F3CFACC9E0615C4F4A7C4D8DAB531B09B6F9C170C533A71D147035B0C591" +
                    "7184EE536593F4414339976C647C5D5A407ADEDB1D560C4FC6777D2972075B8C",
                16
            ),
            e
        )

        val k = BigInteger.parseString(
            "1755163560258504995406282799211252803334510317477377916502" +
                "081442431820570750344461029867509625089092272358661268724735168078105417" +
                "47529710309879958632945"
        )
        assertEquals(
            BigInteger.parseString(
                "359E7F4B1410FEACC570456C6801496946312120B39D019D455986E364F3" +
                    "65886748ED7A44B3E794434006011842286212273A6D14CF70EA3AF71BB1AE679F1",
                16
            ),
            k
        )

        val paramSet = WeierstrassEllipticCurvesParamSet(p, a, b, q, q, pointP)
        val eSign = signGen(e, d, paramSet, k)

        val len = q.bitCount() / 4

        val rVectorStr = eSign.substring(0, len)
        val sVectorStr = eSign.substring(len, 2 * len)

        val r = BigInteger.parseString(rVectorStr, 16)
        val s = BigInteger.parseString(sVectorStr, 16)

        val rCh = BigInteger.parseString(
            "24892044770313492650728646430321477536674513192821314440274986373" +
                "576110928102217951018714129288237168059598287083302842436534530853" +
                "22004442442534151761462"
        )

        assertEquals(
            BigInteger.parseString(
                "2F86FA60A081091A23DD795E1E3C689EE512A3C82EE0DCC2643C78EEA8FCAC" +
                    "D35492558486B20F1C9EC197C90699850260C93BCBCD9C5C3317E19344E173AE36",
                16
            ),
            rCh
        )

        assertEquals(rCh, r)

        val sCh = BigInteger.parseString(
            "8645232217076695190388492973829369170750237358484315799195987" +
                "99313385180564748877195639672460179421760770893278030956807690115" +
                "822709903853682831835159370"
        )

        assertEquals(
            BigInteger.parseString(
                "1081B394696FFE8E6585E7A9362D26B6325F56778AADBC081C0BFBE933D52FF58" +
                    "23CE288E8C4F362526080DF7F70CE406A6EEB1F56919CB92A9853BDE73E5B4A",
                16
            ),
            sCh
        )

        assertEquals(s, sCh)

        assertTrue(signValidate(e, r, s, pointQ, paramSet))
    }
}
