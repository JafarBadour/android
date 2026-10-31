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

import java.math.BigInteger

/**
 * An IPv4 or IPv6 network prefix.
 *
 * Addresses are stored as the network address (all host bits cleared), so two [Cidr] instances
 * describing the same network always compare equal.
 *
 * This class deliberately does not use [java.net.InetAddress] for parsing: that class performs name
 * resolution for anything which is not a numeric literal, and all input handled here originates
 * from either the (untrusted) server configuration or from free-form user input.
 */
class Cidr private constructor(
    /** Network address, 4 bytes for IPv4 and 16 bytes for IPv6. */
    private val address: ByteArray,
    /** Prefix length in bits. */
    val prefixLength: Int,
) : Comparable<Cidr> {

    /** Total number of bits of the address family: 32 for IPv4, 128 for IPv6. */
    val bits: Int get() = address.size * 8

    val isIPv6: Boolean get() = address.size == 16

    /** Lowest address covered by this prefix, as an unsigned integer. */
    val firstAddress: BigInteger get() = BigInteger(1, address)

    /** Highest address covered by this prefix, as an unsigned integer. */
    val lastAddress: BigInteger
        get() = firstAddress.add(blockSize(bits - prefixLength)).subtract(BigInteger.ONE)

    /** `true` when this prefix covers the entire address family, i.e. 0.0.0.0/0 or ::/0. */
    val isDefaultRoute: Boolean get() = prefixLength == 0

    /** `true` when [other] is fully contained in this prefix. */
    fun contains(other: Cidr): Boolean =
        bits == other.bits &&
            firstAddress <= other.firstAddress &&
            other.lastAddress <= lastAddress

    fun overlaps(other: Cidr): Boolean =
        bits == other.bits &&
            firstAddress <= other.lastAddress &&
            other.firstAddress <= lastAddress

    /** The address bytes of the network address. The returned array is a copy. */
    fun addressBytes(): ByteArray = address.copyOf()

    override fun compareTo(other: Cidr): Int {
        if (bits != other.bits) {
            return bits.compareTo(other.bits)
        }
        val byAddress = firstAddress.compareTo(other.firstAddress)
        return if (byAddress != 0) byAddress else prefixLength.compareTo(other.prefixLength)
    }

    override fun equals(other: Any?): Boolean =
        other is Cidr && prefixLength == other.prefixLength && address.contentEquals(other.address)

    override fun hashCode(): Int = address.contentHashCode() * 31 + prefixLength

    /** Canonical textual representation, always including the prefix length. */
    override fun toString(): String = formatAddress(address) + "/" + prefixLength

    companion object {
        private fun blockSize(hostBits: Int): BigInteger = BigInteger.ONE.shiftLeft(hostBits)

        /**
         * Creates a prefix from raw address bytes, clearing any host bits.
         *
         * @throws IllegalArgumentException when the address length or the prefix length is invalid.
         */
        fun of(address: ByteArray, prefixLength: Int): Cidr {
            require(address.size == 4 || address.size == 16) {
                "Address must be 4 or 16 bytes long, got ${address.size}"
            }
            val bits = address.size * 8
            require(prefixLength in 0..bits) { "Invalid prefix length /$prefixLength" }
            val masked = address.copyOf()
            for (bit in prefixLength until bits) {
                masked[bit / 8] = (masked[bit / 8].toInt() and (1 shl (7 - bit % 8)).inv()).toByte()
            }
            return Cidr(masked, prefixLength)
        }

        private fun of(value: BigInteger, prefixLength: Int, bits: Int): Cidr =
            of(toBytes(value, bits / 8), prefixLength)

        /**
         * Parses `address` or `address/prefix`.
         *
         * @return the parsed prefix, or `null` when [text] is not a valid numeric network.
         */
        fun parse(text: String): Cidr? {
            val trimmed = text.trim()
            if (trimmed.isEmpty() || trimmed.length > MAX_INPUT_LENGTH) {
                return null
            }
            val slash = trimmed.lastIndexOf('/')
            val addressPart = if (slash < 0) trimmed else trimmed.substring(0, slash)
            val address = parseAddress(addressPart) ?: return null
            val bits = address.size * 8
            if (slash < 0) {
                return of(address, bits)
            }
            val prefixPart = trimmed.substring(slash + 1)
            if (prefixPart.isEmpty() || prefixPart.length > 3 || !prefixPart.all { it in '0'..'9' }) {
                return null
            }
            val prefixLength = prefixPart.toInt()
            if (prefixLength > bits) {
                return null
            }
            return of(address, prefixLength)
        }

        /**
         * Removes every address in [remove] from [base], per address family.
         *
         * IPv4 and IPv6 are treated completely independently: removing an IPv4 prefix never
         * influences the IPv6 result and vice versa. The result is the minimal list of prefixes
         * covering exactly `base \ remove`, sorted.
         */
        fun subtract(base: Collection<Cidr>, remove: Collection<Cidr>): List<Cidr> =
            perFamily(base) { bits, family ->
                val removals = remove.filter { it.bits == bits }
                difference(mergePrefixes(family), mergePrefixes(removals))
            }

        /**
         * Intersects [a] with [b], per address family.
         *
         * A family which is absent from either side yields no prefixes for that family, which is
         * exactly the desired behaviour: intersecting pushed IPv4-only routes with an IPv6-only
         * include list must not produce any route at all.
         */
        fun intersect(a: Collection<Cidr>, b: Collection<Cidr>): List<Cidr> =
            perFamily(a) { bits, family ->
                val other = mergePrefixes(b.filter { it.bits == bits })
                val result = mutableListOf<Range>()
                for (left in mergePrefixes(family)) {
                    for (right in other) {
                        val start = left.start.max(right.start)
                        val end = left.end.min(right.end)
                        if (start <= end) {
                            result.add(Range(start, end))
                        }
                    }
                }
                mergeRanges(result)
            }

        /** Collapses overlapping and adjacent prefixes into the minimal equivalent list. */
        fun normalize(prefixes: Collection<Cidr>): List<Cidr> =
            perFamily(prefixes) { _, family -> mergePrefixes(family) }

        private fun perFamily(
            input: Collection<Cidr>,
            operation: (bits: Int, family: List<Cidr>) -> List<Range>,
        ): List<Cidr> {
            val result = mutableListOf<Cidr>()
            for (bits in intArrayOf(32, 128)) {
                val family = input.filter { it.bits == bits }
                if (family.isEmpty()) {
                    continue
                }
                for (range in operation(bits, family)) {
                    result.addAll(rangeToPrefixes(range, bits))
                }
            }
            return result.sorted()
        }

        /** Half-open-free, inclusive range of unsigned addresses within a single address family. */
        private class Range(val start: BigInteger, val end: BigInteger)

        private fun mergePrefixes(prefixes: List<Cidr>): List<Range> =
            mergeRanges(prefixes.map { Range(it.firstAddress, it.lastAddress) })

        private fun mergeRanges(ranges: List<Range>): List<Range> {
            if (ranges.isEmpty()) {
                return emptyList()
            }
            val sorted = ranges.sortedWith(compareBy({ it.start }, { it.end }))
            val merged = mutableListOf<Range>()
            var current = sorted.first()
            for (next in sorted.drop(1)) {
                if (next.start <= current.end.add(BigInteger.ONE)) {
                    if (next.end > current.end) {
                        current = Range(current.start, next.end)
                    }
                } else {
                    merged.add(current)
                    current = next
                }
            }
            merged.add(current)
            return merged
        }

        private fun difference(base: List<Range>, remove: List<Range>): List<Range> {
            var remaining = base
            for (cut in remove) {
                val next = mutableListOf<Range>()
                for (range in remaining) {
                    if (cut.end < range.start || cut.start > range.end) {
                        next.add(range)
                        continue
                    }
                    if (range.start < cut.start) {
                        next.add(Range(range.start, cut.start.subtract(BigInteger.ONE)))
                    }
                    if (cut.end < range.end) {
                        next.add(Range(cut.end.add(BigInteger.ONE), range.end))
                    }
                }
                remaining = next
                if (remaining.isEmpty()) {
                    break
                }
            }
            return remaining
        }

        /** Decomposes an inclusive address range into the minimal list of covering prefixes. */
        private fun rangeToPrefixes(range: Range, bits: Int): List<Cidr> {
            val result = mutableListOf<Cidr>()
            var start = range.start
            while (start <= range.end) {
                val count = range.end.subtract(start).add(BigInteger.ONE)
                // Largest power of two the block may have given its alignment...
                val alignment = if (start.signum() == 0) bits else start.lowestSetBit
                // ...and given how many addresses are left.
                val capacity = count.bitLength() - 1
                val hostBits = minOf(alignment, capacity)
                result.add(of(start, bits - hostBits, bits))
                start = start.add(blockSize(hostBits))
            }
            return result
        }

        // region Textual conversion

        private const val MAX_INPUT_LENGTH = 64

        /**
         * Parses a numeric IPv4 or IPv6 address into its raw bytes.
         *
         * Implemented as a hand-written scanner rather than a regular expression: the input is
         * untrusted and no amount of input may cause super-linear work here.
         */
        private fun parseAddress(text: String): ByteArray? =
            if (text.contains(':')) parseIPv6(text) else parseIPv4(text)

        private fun parseIPv4(text: String): ByteArray? {
            val result = ByteArray(4)
            var index = 0
            for (octet in 0 until 4) {
                if (octet > 0) {
                    if (index >= text.length || text[index] != '.') {
                        return null
                    }
                    index++
                }
                var digits = 0
                var value = 0
                while (index < text.length && text[index] in '0'..'9') {
                    value = value * 10 + (text[index] - '0')
                    index++
                    digits++
                    if (digits > 3 || value > 255) {
                        return null
                    }
                }
                if (digits == 0) {
                    return null
                }
                result[octet] = value.toByte()
            }
            return if (index == text.length) result else null
        }

        private fun parseIPv6(text: String): ByteArray? {
            // Zone identifiers have no meaning for a route and are rejected rather than ignored.
            if (text.contains('%')) {
                return null
            }
            val groups = ArrayList<Int>(8)
            var gapIndex = -1
            var index = 0
            if (text.startsWith("::")) {
                gapIndex = 0
                index = 2
                if (index == text.length) {
                    return ByteArray(16)
                }
            } else if (text.startsWith(":")) {
                return null
            }
            while (index < text.length) {
                if (text[index] == ':') {
                    if (gapIndex >= 0) {
                        return null
                    }
                    gapIndex = groups.size
                    index++
                    if (index == text.length) {
                        break
                    }
                    continue
                }
                // A trailing dotted-quad stands for the last two groups. Only the dot of the
                // group we are reading counts: a dot further along belongs to a later group.
                val dot = text.indexOf('.', index)
                val nextColon = text.indexOf(':', index)
                if (dot >= 0 && (nextColon < 0 || dot < nextColon)) {
                    val embedded = parseIPv4(text.substring(index)) ?: return null
                    if (groups.size + 2 > 8) {
                        return null
                    }
                    groups.add((embedded[0].toInt() and 0xff shl 8) or (embedded[1].toInt() and 0xff))
                    groups.add((embedded[2].toInt() and 0xff shl 8) or (embedded[3].toInt() and 0xff))
                    index = text.length
                    break
                }
                var digits = 0
                var value = 0
                while (index < text.length && isHexDigit(text[index])) {
                    value = value * 16 + hexValue(text[index])
                    index++
                    digits++
                    if (digits > 4) {
                        return null
                    }
                }
                if (digits == 0 || groups.size >= 8) {
                    return null
                }
                groups.add(value)
                if (index < text.length) {
                    if (text[index] != ':') {
                        return null
                    }
                    index++
                    if (index == text.length) {
                        // A single trailing colon is only valid as part of "::".
                        return null
                    }
                }
            }
            if (gapIndex < 0) {
                if (groups.size != 8) {
                    return null
                }
            } else {
                if (groups.size >= 8) {
                    return null
                }
                val padding = 8 - groups.size
                repeat(padding) { groups.add(gapIndex, 0) }
            }
            val result = ByteArray(16)
            for (group in 0 until 8) {
                result[group * 2] = (groups[group] shr 8).toByte()
                result[group * 2 + 1] = groups[group].toByte()
            }
            return result
        }

        private fun isHexDigit(c: Char): Boolean =
            c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'

        private fun hexValue(c: Char): Int = when (c) {
            in '0'..'9' -> c - '0'
            in 'a'..'f' -> c - 'a' + 10
            else -> c - 'A' + 10
        }

        private fun toBytes(value: BigInteger, length: Int): ByteArray {
            val magnitude = value.toByteArray()
            val result = ByteArray(length)
            // BigInteger.toByteArray() is big endian and may carry a leading sign byte.
            val copy = minOf(magnitude.size, length)
            System.arraycopy(
                magnitude, magnitude.size - copy,
                result, length - copy,
                copy
            )
            return result
        }

        private fun formatAddress(address: ByteArray): String =
            if (address.size == 4) formatIPv4(address) else formatIPv6(address)

        private fun formatIPv4(address: ByteArray): String = address.joinToString(".") {
            (it.toInt() and 0xff).toString()
        }

        /** Formats an IPv6 address in the shortened form described by RFC 5952. */
        private fun formatIPv6(address: ByteArray): String {
            val groups = IntArray(8) {
                (address[it * 2].toInt() and 0xff shl 8) or (address[it * 2 + 1].toInt() and 0xff)
            }
            var bestStart = -1
            var bestLength = 0
            var runStart = -1
            for (index in 0..8) {
                val isZero = index < 8 && groups[index] == 0
                if (isZero && runStart < 0) {
                    runStart = index
                } else if (!isZero && runStart >= 0) {
                    val length = index - runStart
                    if (length > bestLength) {
                        bestStart = runStart
                        bestLength = length
                    }
                    runStart = -1
                }
            }
            // A run of a single zero group is written out in full.
            if (bestLength < 2) {
                bestStart = -1
            }
            val builder = StringBuilder()
            var index = 0
            while (index < 8) {
                if (index == bestStart) {
                    builder.append("::")
                    index += bestLength
                    continue
                }
                if (builder.isNotEmpty() && !builder.endsWith("::")) {
                    builder.append(':')
                }
                builder.append(Integer.toHexString(groups[index]))
                index++
            }
            return builder.toString()
        }

        // endregion
    }
}
