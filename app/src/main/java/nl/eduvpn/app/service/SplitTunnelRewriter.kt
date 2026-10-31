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
import com.wireguard.config.Interface
import com.wireguard.config.Peer
import de.blinkt.openvpn.VpnProfile
import nl.eduvpn.app.entity.SplitTunnelAppMode
import nl.eduvpn.app.entity.SplitTunnelDnsMode
import nl.eduvpn.app.entity.SplitTunnelMode
import nl.eduvpn.app.entity.SplitTunnelSettings
import nl.eduvpn.app.utils.Cidr
import kotlin.jvm.optionals.getOrNull

/**
 * Applies the user's split tunneling settings to a finished server configuration.
 *
 * Both entry points are pure functions of (server configuration, settings, default-gateway flag).
 * The rewriter keeps no state of its own, so it can — and must — be applied again to every
 * configuration the server hands out, including after an expiry or authorization refresh.
 */
object SplitTunnelRewriter {

    /**
     * Rewrites a WireGuard configuration.
     *
     * Keys, endpoint, keep-alive, MTU and the ProxyGuard endpoint are passed through untouched;
     * only `AllowedIPs`, the DNS attribute and the application lists change.
     *
     * @param config the configuration as handed out by the server.
     * @param settings the user's settings for this server.
     * @param isDefaultGateway the server's `default_gateway` flag. When `false` the server already
     *   pushes a partial route set, so [SplitTunnelMode.INCLUDE_ONLY] intersects with the pushed
     *   `AllowedIPs` instead of replacing them, and [SplitTunnelMode.EXCLUDE] subtracts from them.
     * @return the rewritten configuration, or [config] itself when nothing needs to change.
     */
    fun rewrite(
        config: Config,
        settings: SplitTunnelSettings,
        isDefaultGateway: Boolean,
    ): Config {
        if (!settings.isActive) {
            return config
        }
        val original = config.`interface`
        val tunnelPrefixes = original.addresses.mapNotNull { Cidr.parse(it.toString()) }
        val interfaceBuilder = Interface.Builder()
            .setKeyPair(original.keyPair)
            .addAddresses(original.addresses)
        original.listenPort.getOrNull()?.let { interfaceBuilder.setListenPort(it) }
        original.mtu.getOrNull()?.let { interfaceBuilder.setMtu(it) }
        when (settings.dns) {
            // Keep what the server pushed. Note that Android only sends queries for the pushed
            // search domains to a VPN which does not claim a default route, so on a split tunnel
            // SERVER behaves like SPLIT. This is a platform rule we cannot override.
            SplitTunnelDnsMode.SERVER, SplitTunnelDnsMode.SPLIT -> {
                interfaceBuilder.addDnsServers(original.dnsServers)
                interfaceBuilder.addDnsSearchDomains(original.dnsSearchDomains)
            }
            // Drop the pushed resolvers entirely and keep using the system resolver.
            SplitTunnelDnsMode.SYSTEM -> Unit
        }
        when (settings.appMode) {
            SplitTunnelAppMode.BYPASS -> interfaceBuilder.excludeApplications(settings.apps)
            SplitTunnelAppMode.ONLY -> interfaceBuilder.includeApplications(settings.apps)
        }

        val configBuilder = Config.Builder().setInterface(interfaceBuilder.build())
        for (peer in config.peers) {
            val peerBuilder = Peer.Builder().setPublicKey(peer.publicKey)
            peer.endpoint.getOrNull()?.let { peerBuilder.setEndpoint(it) }
            peer.preSharedKey.getOrNull()?.let { peerBuilder.setPreSharedKey(it) }
            peer.persistentKeepalive.getOrNull()?.let { peerBuilder.setPersistentKeepalive(it) }
            peer.proxyEndpoint?.let { peerBuilder.setProxyEndpoint(it) }
            val allowedIps = allowedIpsFor(peer, settings, isDefaultGateway, tunnelPrefixes)
            if (allowedIps.isNotEmpty()) {
                // parseAllowedIPs() is used rather than addAllowedIp() because it turns a parse
                // failure into the BadConfigException the caller already handles.
                peerBuilder.parseAllowedIPs(allowedIps.joinToString(", "))
            }
            configBuilder.addPeer(peerBuilder.build())
        }
        return configBuilder.build()
    }

    /**
     * Computes the `AllowedIPs` of a single peer.
     *
     * Visible for testing; [rewrite] is the supported entry point.
     */
    internal fun allowedIpsFor(
        peer: Peer,
        settings: SplitTunnelSettings,
        isDefaultGateway: Boolean,
        tunnelPrefixes: List<Cidr> = emptyList(),
    ): List<Cidr> {
        val pushed = peer.allowedIps.mapNotNull { Cidr.parse(it.toString()) }
        val configured = settings.parsedRoutes()
        var result = when (settings.mode) {
            // Per-app or DNS-only settings must leave the routes — and with them the kill-switch
            // behaviour GoBackend derives from a default route — exactly as the server wrote them.
            SplitTunnelMode.OFF -> pushed
            // WireGuard has no exclude syntax, so the complement is computed here. IPv4 and IPv6
            // are subtracted independently: excluding only IPv4 ranges leaves ::/0 in place.
            SplitTunnelMode.EXCLUDE -> Cidr.subtract(pushed, configured)
            SplitTunnelMode.INCLUDE_ONLY ->
                if (isDefaultGateway) {
                    Cidr.normalize(configured)
                } else {
                    // The server already narrowed the route set; never widen it.
                    Cidr.intersect(pushed, configured)
                }
        }
        if (settings.mode != SplitTunnelMode.OFF && settings.alwaysIncludeTunnelSubnet) {
            // The tunnel's own subnet must stay reachable whatever the user entered.
            result = Cidr.normalize(result + tunnelPrefixes)
            // Routing the peer endpoint into the tunnel would break the tunnel itself.
            endpointPrefix(peer)?.let { result = Cidr.subtract(result, listOf(it)) }
        }
        return result
    }

    /** The peer endpoint as a host prefix, or `null` when it is a name rather than a literal. */
    private fun endpointPrefix(peer: Peer): Cidr? {
        val host = peer.endpoint.getOrNull()?.host ?: return null
        return Cidr.parse(host)
    }

    /**
     * Builds the extra OpenVPN directives which implement the user's settings.
     *
     * The result is appended to the configuration generated from the [VpnProfile], where OpenVPN's
     * last-wins rules make it override anything above it. An empty string means "change nothing".
     *
     * @param settings the user's settings for this server.
     * @param isDefaultGateway the server's `default_gateway` flag.
     */
    fun openVpnDirectives(settings: SplitTunnelSettings, isDefaultGateway: Boolean): String {
        if (settings.mode == SplitTunnelMode.OFF && settings.dns != SplitTunnelDnsMode.SYSTEM) {
            return ""
        }
        val lines = mutableListOf<String>()
        val configured = Cidr.normalize(settings.parsedRoutes())
        when (settings.mode) {
            SplitTunnelMode.OFF -> Unit

            SplitTunnelMode.INCLUDE_ONLY -> {
                // Drop every route the server pushes, then install only what the user listed.
                // route-nopull is deliberately not used: from OpenVPN 2.5 on it also drops the
                // pushed DNS options, which the DNS setting controls separately.
                lines.add("""pull-filter ignore "redirect-gateway"""")
                lines.add("""pull-filter ignore "redirect-private"""")
                // The trailing space keeps this from matching "route-gateway" or "route-metric".
                lines.add("""pull-filter ignore "route """")
                lines.add("""pull-filter ignore "route-ipv6 """")
                for (route in configured) {
                    lines.add(routeDirective(route, viaVpn = true))
                }
                if (!isDefaultGateway) {
                    lines.add(
                        "# Profile is not default-gateway: the routes above replace the pushed " +
                            "ones, so destinations the server does not route are unreachable."
                    )
                }
            }

            SplitTunnelMode.EXCLUDE -> {
                // Keep the full tunnel, but send the excluded networks to the physical gateway.
                if (isDefaultGateway) {
                    lines.add("redirect-gateway def1 ipv6")
                }
                for (route in configured) {
                    lines.add(routeDirective(route, viaVpn = false))
                }
            }
        }
        when (settings.dns) {
            // Keep the pushed resolvers. Android only sends queries for the pushed search domains
            // to a VPN without a default route, which is what SPLIT asks for.
            SplitTunnelDnsMode.SERVER, SplitTunnelDnsMode.SPLIT -> Unit
            SplitTunnelDnsMode.SYSTEM -> lines.add("""pull-filter ignore "dhcp-option DNS"""")
        }
        return if (lines.isEmpty()) "" else lines.joinToString("\n")
    }

    private fun routeDirective(route: Cidr, viaVpn: Boolean): String {
        val gateway = if (viaVpn) "vpn_gateway" else "net_gateway"
        if (route.isIPv6) {
            // route-ipv6 takes a prefix and, for an exclusion, an explicit gateway.
            return if (viaVpn) "route-ipv6 $route" else "route-ipv6 $route $gateway"
        }
        return "route ${route.addressString()} ${route.netmaskString()} $gateway"
    }

    /**
     * Applies the settings to an already parsed OpenVPN profile.
     *
     * The route directives go through [VpnProfile.mCustomConfigOptions] rather than through
     * [VpnProfile.mCustomRoutes] and friends, because ics-openvpn regenerates the configuration
     * from the profile fields and only emits the excluded-route fields when the profile does not
     * use a default route. Writing the directives verbatim keeps one code path for both split
     * tunneling modes and keeps the generated text identical to what the Windows client writes.
     */
    fun applyTo(profile: VpnProfile, settings: SplitTunnelSettings, isDefaultGateway: Boolean) {
        if (!settings.isActive) {
            return
        }
        val directives = openVpnDirectives(settings, isDefaultGateway)
        if (directives.isNotEmpty()) {
            profile.mUseCustomConfig = true
            profile.mCustomConfigOptions = listOf(profile.mCustomConfigOptions, directives)
                .filter { !it.isNullOrBlank() }
                .joinToString("\n")
        }
        profile.mAllowedAppsVpn = HashSet(settings.apps)
        profile.mAllowedAppsVpnAreDisallowed = settings.appMode == SplitTunnelAppMode.BYPASS
    }

    private fun Cidr.addressString(): String = toString().substringBefore('/')

    private fun Cidr.netmaskString(): String {
        val bytes = ByteArray(4)
        for (bit in 0 until prefixLength) {
            bytes[bit / 8] = (bytes[bit / 8].toInt() or (1 shl (7 - bit % 8))).toByte()
        }
        return bytes.joinToString(".") { (it.toInt() and 0xff).toString() }
    }
}
