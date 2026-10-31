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

package nl.eduvpn.app.service

import com.wireguard.config.Config
import nl.eduvpn.app.entity.SplitTunnelAppMode
import nl.eduvpn.app.entity.SplitTunnelDnsMode
import nl.eduvpn.app.entity.SplitTunnelMode
import nl.eduvpn.app.entity.SplitTunnelSettings
import nl.eduvpn.app.utils.Cidr
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.BufferedReader
import java.io.StringReader

class SplitTunnelRewriterTest {

    private fun parse(text: String): Config =
        Config.parse(BufferedReader(StringReader(text.trimIndent())))

    /** A full-tunnel WireGuard configuration as an eduVPN server hands it out. */
    private val fullTunnelConfig = """
        [Interface]
        PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
        Address = 10.43.0.2/24, fd43::2/112
        DNS = 10.43.0.1, fd43::1, eduvpn.example.org
        MTU = 1392

        [Peer]
        PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
        AllowedIPs = 0.0.0.0/0, ::/0
        Endpoint = 145.100.1.1:51820
        PersistentKeepalive = 25
    """

    private val splitRoutes = listOf("10.0.0.0/8", "130.89.0.0/16")

    /**
     * The peer's allowed IPs in canonical notation.
     *
     * The WireGuard library renders an [java.net.InetAddress] with `getHostAddress()`, which spells
     * IPv6 out in full, so the values are put through [Cidr] to compare them the way the user sees
     * them.
     */
    private fun allowedIps(config: Config): List<String> =
        config.peers.single().allowedIps.map { requireNotNull(Cidr.parse(it.toString())).toString() }

    // region WireGuard

    @Test
    fun offLeavesTheConfigurationUntouched() {
        val config = parse(fullTunnelConfig)
        val result = SplitTunnelRewriter.rewrite(config, SplitTunnelSettings.OFF, true)
        // Same instance, so the generated tunnel configuration is byte-identical by construction.
        assertSame(config, result)
        assertEquals(config.toWgQuickString(), result.toWgQuickString())
    }

    @Test
    fun includeOnlyReplacesAllowedIpsOnADefaultGatewayProfile() {
        val result = SplitTunnelRewriter.rewrite(
            parse(fullTunnelConfig),
            SplitTunnelSettings(mode = SplitTunnelMode.INCLUDE_ONLY, routes = splitRoutes),
            isDefaultGateway = true,
        )
        // The interface prefixes are added back so the tunnel subnet stays reachable.
        assertEquals(
            listOf("10.0.0.0/8", "130.89.0.0/16", "fd43::/112"),
            allowedIps(result)
        )
    }

    @Test
    fun includeOnlyIntersectsOnANonDefaultGatewayProfile() {
        val config = parse(
            """
            [Interface]
            PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
            Address = 10.43.0.2/24

            [Peer]
            PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
            AllowedIPs = 130.89.0.0/16, 145.100.0.0/16
            Endpoint = 145.100.1.1:51820
            """
        )
        val result = SplitTunnelRewriter.rewrite(
            config,
            SplitTunnelSettings(
                mode = SplitTunnelMode.INCLUDE_ONLY,
                routes = listOf("130.89.0.0/24", "10.0.0.0/8"),
            ),
            isDefaultGateway = false,
        )
        // 10.0.0.0/8 was never pushed, so it is not added; the /24 narrows the pushed /16.
        assertEquals(listOf("10.43.0.0/24", "130.89.0.0/24"), allowedIps(result))
    }

    @Test
    fun excludeComputesTheComplement() {
        val result = SplitTunnelRewriter.rewrite(
            parse(fullTunnelConfig),
            SplitTunnelSettings(
                mode = SplitTunnelMode.EXCLUDE,
                routes = listOf("192.168.0.0/16"),
            ),
            isDefaultGateway = true,
        )
        val ips = allowedIps(result)
        // The excluded LAN is gone, the IPv6 default route is untouched, and the endpoint is
        // carved out so the tunnel can still reach its own peer.
        assertFalse("0.0.0.0/0" in ips)
        assertFalse("192.168.0.0/16" in ips)
        assertTrue("::/0" in ips)
        assertTrue(ips.none { Cidr.parse(it)?.contains(Cidr.parse("192.168.0.0/16")!!) == true })
        assertTrue(ips.none { Cidr.parse(it)?.contains(Cidr.parse("145.100.1.1/32")!!) == true })
    }

    @Test
    fun excludeOnlyIPv4KeepsIPv6FullyTunnelled() {
        val result = SplitTunnelRewriter.rewrite(
            parse(fullTunnelConfig),
            SplitTunnelSettings(mode = SplitTunnelMode.EXCLUDE, routes = listOf("10.0.0.0/8")),
            isDefaultGateway = true,
        )
        assertTrue("::/0" in allowedIps(result))
    }

    @Test
    fun keysEndpointAndMtuSurvive() {
        val config = parse(fullTunnelConfig)
        val result = SplitTunnelRewriter.rewrite(
            config,
            SplitTunnelSettings(mode = SplitTunnelMode.INCLUDE_ONLY, routes = splitRoutes),
            isDefaultGateway = true,
        )
        assertEquals(config.`interface`.keyPair.publicKey, result.`interface`.keyPair.publicKey)
        assertEquals(config.`interface`.mtu, result.`interface`.mtu)
        assertEquals(config.`interface`.addresses, result.`interface`.addresses)
        assertEquals(
            config.peers.single().publicKey,
            result.peers.single().publicKey
        )
        assertEquals(
            config.peers.single().endpoint.get().toString(),
            result.peers.single().endpoint.get().toString()
        )
        assertEquals(
            config.peers.single().persistentKeepalive,
            result.peers.single().persistentKeepalive
        )
    }

    @Test
    fun dnsServerAndSplitKeepThePushedResolvers() {
        for (mode in listOf(SplitTunnelDnsMode.SERVER, SplitTunnelDnsMode.SPLIT)) {
            val config = parse(fullTunnelConfig)
            val result = SplitTunnelRewriter.rewrite(
                config,
                SplitTunnelSettings(
                    mode = SplitTunnelMode.EXCLUDE,
                    routes = listOf("192.168.0.0/16"),
                    dns = mode,
                ),
                isDefaultGateway = true,
            )
            assertEquals(config.`interface`.dnsServers, result.`interface`.dnsServers)
            assertEquals(
                config.`interface`.dnsSearchDomains,
                result.`interface`.dnsSearchDomains
            )
        }
    }

    @Test
    fun dnsOnlySettingsKeepTheRoutesUnchanged() {
        val result = SplitTunnelRewriter.rewrite(
            parse(fullTunnelConfig),
            SplitTunnelSettings(dns = SplitTunnelDnsMode.SYSTEM),
            isDefaultGateway = true,
        )
        assertEquals(listOf("0.0.0.0/0", "::/0"), allowedIps(result))
        assertTrue(result.`interface`.dnsServers.isEmpty())
    }

    @Test
    fun dnsSystemDropsThePushedResolvers() {
        val result = SplitTunnelRewriter.rewrite(
            parse(fullTunnelConfig),
            SplitTunnelSettings(
                mode = SplitTunnelMode.EXCLUDE,
                routes = listOf("192.168.0.0/16"),
                dns = SplitTunnelDnsMode.SYSTEM,
            ),
            isDefaultGateway = true,
        )
        assertTrue(result.`interface`.dnsServers.isEmpty())
        assertTrue(result.`interface`.dnsSearchDomains.isEmpty())
    }

    @Test
    fun perAppListsLandOnTheInterface() {
        val bypass = SplitTunnelRewriter.rewrite(
            parse(fullTunnelConfig),
            SplitTunnelSettings(apps = listOf("org.mozilla.firefox")),
            isDefaultGateway = true,
        )
        assertEquals(setOf("org.mozilla.firefox"), bypass.`interface`.excludedApplications)
        assertTrue(bypass.`interface`.includedApplications.isEmpty())

        val only = SplitTunnelRewriter.rewrite(
            parse(fullTunnelConfig),
            SplitTunnelSettings(
                apps = listOf("org.mozilla.firefox"),
                appMode = SplitTunnelAppMode.ONLY,
            ),
            isDefaultGateway = true,
        )
        assertEquals(setOf("org.mozilla.firefox"), only.`interface`.includedApplications)
        assertTrue(only.`interface`.excludedApplications.isEmpty())
    }

    @Test
    fun perAppOnlyKeepsTheRoutesUnchanged() {
        val config = parse(fullTunnelConfig)
        val result = SplitTunnelRewriter.rewrite(
            config,
            SplitTunnelSettings(apps = listOf("org.mozilla.firefox")),
            isDefaultGateway = true,
        )
        // Mode is OFF, so the routes — and with them the kill-switch behaviour GoBackend derives
        // from a default route — must be exactly what the server wrote.
        assertEquals(listOf("0.0.0.0/0", "::/0"), allowedIps(result))
    }

    @Test
    fun invalidRoutesAreIgnoredRatherThanFatal() {
        val result = SplitTunnelRewriter.rewrite(
            parse(fullTunnelConfig),
            SplitTunnelSettings(
                mode = SplitTunnelMode.INCLUDE_ONLY,
                routes = listOf("10.0.0.0/8", "nonsense", "999.0.0.0/8"),
            ),
            isDefaultGateway = true,
        )
        assertTrue("10.0.0.0/8" in allowedIps(result))
    }

    @Test
    fun rewriteIsPure() {
        val settings =
            SplitTunnelSettings(mode = SplitTunnelMode.EXCLUDE, routes = listOf("192.168.0.0/16"))
        val first = SplitTunnelRewriter.rewrite(parse(fullTunnelConfig), settings, true)
        val second = SplitTunnelRewriter.rewrite(parse(fullTunnelConfig), settings, true)
        assertEquals(first.toWgQuickString(), second.toWgQuickString())
        // Applying the rewrite to its own output is idempotent for EXCLUDE.
        val third = SplitTunnelRewriter.rewrite(first, settings, true)
        assertEquals(first.toWgQuickString(), third.toWgQuickString())
    }

    // endregion

    // region OpenVPN

    @Test
    fun offEmitsNoDirectives() {
        assertEquals("", SplitTunnelRewriter.openVpnDirectives(SplitTunnelSettings.OFF, true))
    }

    @Test
    fun includeOnlyDirectives() {
        val directives = SplitTunnelRewriter.openVpnDirectives(
            SplitTunnelSettings(mode = SplitTunnelMode.INCLUDE_ONLY, routes = splitRoutes),
            isDefaultGateway = true,
        )
        assertEquals(
            """
            pull-filter ignore "redirect-gateway"
            pull-filter ignore "redirect-private"
            pull-filter ignore "route "
            pull-filter ignore "route-ipv6 "
            route 10.0.0.0 255.0.0.0 vpn_gateway
            route 130.89.0.0 255.255.0.0 vpn_gateway
            """.trimIndent(),
            directives
        )
    }

    @Test
    fun includeOnlyDirectivesForIPv6() {
        val directives = SplitTunnelRewriter.openVpnDirectives(
            SplitTunnelSettings(
                mode = SplitTunnelMode.INCLUDE_ONLY,
                routes = listOf("2001:db8::/32"),
            ),
            isDefaultGateway = true,
        )
        assertTrue(directives.contains("route-ipv6 2001:db8::/32"))
    }

    @Test
    fun excludeDirectives() {
        val directives = SplitTunnelRewriter.openVpnDirectives(
            SplitTunnelSettings(
                mode = SplitTunnelMode.EXCLUDE,
                routes = listOf("192.168.0.0/16", "2001:db8::/32"),
            ),
            isDefaultGateway = true,
        )
        assertEquals(
            """
            redirect-gateway def1 ipv6
            route 192.168.0.0 255.255.0.0 net_gateway
            route-ipv6 2001:db8::/32 net_gateway
            """.trimIndent(),
            directives
        )
    }

    @Test
    fun excludeOnANonDefaultGatewayProfileKeepsThePushedRoutes() {
        val directives = SplitTunnelRewriter.openVpnDirectives(
            SplitTunnelSettings(
                mode = SplitTunnelMode.EXCLUDE,
                routes = listOf("192.168.0.0/16"),
            ),
            isDefaultGateway = false,
        )
        // No redirect-gateway is forced on a profile which never had a default route.
        assertEquals("route 192.168.0.0 255.255.0.0 net_gateway", directives)
    }

    @Test
    fun dnsSystemDropsThePushedResolversForOpenVpn() {
        val directives = SplitTunnelRewriter.openVpnDirectives(
            SplitTunnelSettings(dns = SplitTunnelDnsMode.SYSTEM),
            isDefaultGateway = true,
        )
        assertEquals("""pull-filter ignore "dhcp-option DNS"""", directives)
    }

    @Test
    fun routeFiltersCannotMatchRouteGateway() {
        val directives = SplitTunnelRewriter.openVpnDirectives(
            SplitTunnelSettings(mode = SplitTunnelMode.INCLUDE_ONLY, routes = splitRoutes),
            isDefaultGateway = true,
        )
        // The trailing space is what keeps route-gateway, route-metric and route-delay pushes.
        assertTrue(directives.contains("""pull-filter ignore "route """"))
        assertFalse(directives.contains("""pull-filter ignore "route""""))
    }

    // endregion

    /**
     * Both protocols must describe the same route set for the same settings, so that a failover
     * from WireGuard to OpenVPN does not silently widen or narrow the tunnel.
     */
    @Test
    fun bothProtocolsAgreeOnTheRouteSet() {
        val settings =
            SplitTunnelSettings(mode = SplitTunnelMode.INCLUDE_ONLY, routes = splitRoutes)
        val wireGuard = SplitTunnelRewriter
            .rewrite(parse(fullTunnelConfig), settings, true)
            .peers.single().allowedIps
            .mapNotNull { Cidr.parse(it.toString()) }
            // The interface prefixes are implicit in OpenVPN: they come from the ifconfig push.
            .filterNot { it.toString() in listOf("10.43.0.0/24", "fd43::/112") }
            .map { it.toString() }
            .sorted()

        val openVpn = SplitTunnelRewriter.openVpnDirectives(settings, true)
            .lines()
            .filter { it.startsWith("route ") || it.startsWith("route-ipv6 ") }
            .map { line ->
                val parts = line.split(' ')
                if (parts[0] == "route-ipv6") {
                    parts[1]
                } else {
                    "${parts[1]}/${maskToPrefixLength(parts[2])}"
                }
            }
            .sorted()

        assertEquals(wireGuard, openVpn)
    }

    private fun maskToPrefixLength(mask: String): Int =
        mask.split('.').sumOf { Integer.bitCount(it.toInt()) }
}
