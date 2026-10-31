/*
 *  This file is part of eduVPN.
 *
 *     eduVPN is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     eduVPN is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with eduVPN.  If not, see <http://www.gnu.org/licenses/>.
 */

package nl.eduvpn.app.utils

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger

class CidrMathTest {

    private fun cidr(text: String): Cidr =
        requireNotNull(Cidr.parse(text)) { "Expected $text to parse" }

    private fun texts(prefixes: List<Cidr>): List<String> = prefixes.map { it.toString() }

    // region Parsing

    @Test
    fun parsesIPv4() {
        assertEquals("10.0.0.0/8", cidr("10.0.0.0/8").toString())
        assertEquals("0.0.0.0/0", cidr("0.0.0.0/0").toString())
        assertEquals("1.2.3.4/32", cidr("1.2.3.4").toString())
        assertEquals(32, cidr("1.2.3.4").bits)
        assertFalse(cidr("10.0.0.0/8").isIPv6)
    }

    @Test
    fun clearsHostBits() {
        assertEquals("10.0.0.0/8", cidr("10.1.2.3/8").toString())
        assertEquals("192.168.0.0/16", cidr("192.168.5.7/16").toString())
        assertEquals("2001:db8::/32", cidr("2001:db8:1234::1/32").toString())
    }

    @Test
    fun parsesIPv6() {
        assertEquals("::/0", cidr("::/0").toString())
        assertEquals("::1/128", cidr("::1").toString())
        assertEquals("2001:db8::/32", cidr("2001:db8::/32").toString())
        assertEquals("fd00::/8", cidr("fd00::/8").toString())
        assertTrue(cidr("::/0").isIPv6)
        assertEquals(128, cidr("::/0").bits)
    }

    @Test
    fun parsesIPv6WithEmbeddedIPv4() {
        assertEquals("::ffff:102:304/128", cidr("::ffff:1.2.3.4").toString())
    }

    @Test
    fun formatsIPv6TheShortestWay() {
        // A single zero group is written out rather than compressed.
        assertEquals("2001:db8:0:1:1:1:1:1/128", cidr("2001:db8:0:1:1:1:1:1").toString())
        assertEquals("2001:db8::1/128", cidr("2001:0db8:0000:0000:0000:0000:0000:0001").toString())
    }

    @Test
    fun rejectsInvalidInput() {
        for (invalid in listOf(
            "", "   ", "not-an-address", "10.0.0", "10.0.0.0.0", "256.0.0.0", "10.0.0.0/33",
            "10.0.0.0/", "10.0.0.0/-1", "10.0.0.0/08x", "::/129", "fe80::1%eth0", ":::1",
            "1:2:3:4:5:6:7:8:9", "2001:db8::/32/8", "10.0.0.0 /8",
        )) {
            assertNull("Expected '$invalid' to be rejected", Cidr.parse(invalid))
        }
    }

    @Test
    fun acceptsSurroundingWhitespace() {
        assertNotNull(Cidr.parse("  10.0.0.0/8  "))
    }

    @Test
    fun rejectsOverlyLongInput() {
        assertNull(Cidr.parse("1".repeat(200)))
    }

    // endregion

    // region Subtraction

    @Test
    fun subtractsPrivateRangeFromDefaultRoute() {
        val result = Cidr.subtract(listOf(cidr("0.0.0.0/0")), listOf(cidr("10.0.0.0/8")))
        assertEquals(
            listOf(
                "0.0.0.0/5",
                "8.0.0.0/7",
                "11.0.0.0/8",
                "12.0.0.0/6",
                "16.0.0.0/4",
                "32.0.0.0/3",
                "64.0.0.0/2",
                "128.0.0.0/1",
            ),
            texts(result)
        )
        assertCoversExactly(listOf(cidr("0.0.0.0/0")), listOf(cidr("10.0.0.0/8")), result)
    }

    @Test
    fun subtractsLanFromDefaultRoute() {
        val result = Cidr.subtract(listOf(cidr("0.0.0.0/0")), listOf(cidr("192.168.0.0/16")))
        assertCoversExactly(listOf(cidr("0.0.0.0/0")), listOf(cidr("192.168.0.0/16")), result)
        assertTrue("192.168.0.0/16" !in texts(result))
        // Everything outside the LAN stays in, so the first prefix starts at 0.0.0.0.
        assertEquals("0.0.0.0/1", texts(result).first())
    }

    @Test
    fun keepsAddressFamiliesIndependent() {
        val base = listOf(cidr("0.0.0.0/0"), cidr("::/0"))
        val result = Cidr.subtract(base, listOf(cidr("192.168.0.0/16")))
        // Only IPv4 was excluded, so the IPv6 default route survives untouched.
        assertTrue("::/0" in texts(result))
        assertFalse("0.0.0.0/0" in texts(result))
    }

    @Test
    fun subtractsIPv6Range() {
        val result = Cidr.subtract(listOf(cidr("::/0")), listOf(cidr("2001:db8::/32")))
        assertCoversExactly(listOf(cidr("::/0")), listOf(cidr("2001:db8::/32")), result)
        assertFalse("2001:db8::/32" in texts(result))
    }

    @Test
    fun handlesOverlappingAndNestedExclusions() {
        val base = listOf(cidr("10.0.0.0/8"))
        val remove = listOf(
            cidr("10.1.0.0/16"),
            cidr("10.1.2.0/24"), // nested in the previous one
            cidr("10.2.0.0/15"), // overlaps 10.3.0.0/16 as well
            cidr("10.3.0.0/16"),
        )
        val result = Cidr.subtract(base, remove)
        assertEquals(listOf("10.0.0.0/16", "10.4.0.0/14", "10.8.0.0/13", "10.16.0.0/12", "10.32.0.0/11", "10.64.0.0/10", "10.128.0.0/9"), texts(result))
        assertCoversExactly(base, remove, result)
    }

    @Test
    fun subtractingEverythingYieldsNothing() {
        val result = Cidr.subtract(
            listOf(cidr("10.0.0.0/8")),
            listOf(cidr("10.0.0.0/9"), cidr("10.128.0.0/9"))
        )
        assertEquals(emptyList<String>(), texts(result))
    }

    @Test
    fun subtractingAnUnrelatedRangeChangesNothing() {
        val result = Cidr.subtract(listOf(cidr("10.0.0.0/8")), listOf(cidr("192.168.0.0/16")))
        assertEquals(listOf("10.0.0.0/8"), texts(result))
    }

    @Test
    fun carvesOutASingleHost() {
        val result = Cidr.subtract(listOf(cidr("0.0.0.0/0")), listOf(cidr("145.100.1.1/32")))
        assertCoversExactly(listOf(cidr("0.0.0.0/0")), listOf(cidr("145.100.1.1/32")), result)
        // 2^32 - 1 addresses need 32 prefixes.
        assertEquals(32, result.size)
    }

    // endregion

    // region Intersection and normalisation

    @Test
    fun intersectsWithPushedRoutes() {
        val pushed = listOf(cidr("130.89.0.0/16"), cidr("145.100.0.0/16"))
        val wanted = listOf(cidr("130.89.0.0/24"), cidr("10.0.0.0/8"))
        val result = Cidr.intersect(pushed, wanted)
        // 10.0.0.0/8 is not pushed, so it is not routed; the /24 is narrowed from the /16.
        assertEquals(listOf("130.89.0.0/24"), texts(result))
    }

    @Test
    fun intersectionOfDisjointFamiliesIsEmpty() {
        val result = Cidr.intersect(listOf(cidr("10.0.0.0/8")), listOf(cidr("2001:db8::/32")))
        assertEquals(emptyList<String>(), texts(result))
    }

    @Test
    fun normalizeMergesAdjacentPrefixes() {
        val result = Cidr.normalize(listOf(cidr("10.0.0.0/9"), cidr("10.128.0.0/9")))
        assertEquals(listOf("10.0.0.0/8"), texts(result))
    }

    @Test
    fun normalizeDropsDuplicatesAndNestedPrefixes() {
        val result = Cidr.normalize(
            listOf(cidr("10.0.0.0/8"), cidr("10.0.0.0/8"), cidr("10.1.0.0/16"))
        )
        assertEquals(listOf("10.0.0.0/8"), texts(result))
    }

    @Test
    fun containsAndOverlaps() {
        assertTrue(cidr("10.0.0.0/8").contains(cidr("10.1.0.0/16")))
        assertFalse(cidr("10.1.0.0/16").contains(cidr("10.0.0.0/8")))
        assertTrue(cidr("10.0.0.0/8").overlaps(cidr("10.1.0.0/16")))
        assertFalse(cidr("10.0.0.0/8").overlaps(cidr("11.0.0.0/8")))
        // Different families never contain or overlap each other.
        assertFalse(cidr("0.0.0.0/0").contains(cidr("::/0")))
        assertFalse(cidr("0.0.0.0/0").overlaps(cidr("::/0")))
    }

    // endregion

    /**
     * Reference check: compares the result against the address set computed independently with
     * plain interval arithmetic, so a wrong prefix decomposition cannot slip through.
     */
    private fun assertCoversExactly(
        base: List<Cidr>,
        removed: List<Cidr>,
        result: List<Cidr>,
    ) {
        for (family in listOf(32, 128)) {
            val expected = intervals(base.filter { it.bits == family })
                .let { subtractIntervals(it, intervals(removed.filter { it.bits == family })) }
            val actual = intervals(result.filter { it.bits == family })
            assertEquals("Address set differs for /$family", expected, actual)
        }
        // Every emitted prefix must be aligned, which `Cidr.of` guarantees by construction.
        for (prefix in result) {
            assertEquals(prefix, requireNotNull(Cidr.parse(prefix.toString())))
        }
    }

    private fun intervals(prefixes: List<Cidr>): List<Pair<BigInteger, BigInteger>> {
        val sorted = prefixes
            .map { it.firstAddress to it.lastAddress }
            .sortedBy { it.first }
        val merged = mutableListOf<Pair<BigInteger, BigInteger>>()
        for (interval in sorted) {
            val last = merged.lastOrNull()
            if (last != null && interval.first <= last.second.add(BigInteger.ONE)) {
                merged[merged.size - 1] = last.first to last.second.max(interval.second)
            } else {
                merged.add(interval)
            }
        }
        return merged
    }

    private fun subtractIntervals(
        base: List<Pair<BigInteger, BigInteger>>,
        cuts: List<Pair<BigInteger, BigInteger>>,
    ): List<Pair<BigInteger, BigInteger>> {
        var remaining = base
        for (cut in cuts) {
            val next = mutableListOf<Pair<BigInteger, BigInteger>>()
            for (interval in remaining) {
                if (cut.second < interval.first || cut.first > interval.second) {
                    next.add(interval)
                    continue
                }
                if (interval.first < cut.first) {
                    next.add(interval.first to cut.first.subtract(BigInteger.ONE))
                }
                if (cut.second < interval.second) {
                    next.add(cut.second.add(BigInteger.ONE) to interval.second)
                }
            }
            remaining = next
        }
        return remaining
    }
}
