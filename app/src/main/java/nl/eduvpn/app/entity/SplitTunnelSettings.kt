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

package nl.eduvpn.app.entity

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import nl.eduvpn.app.utils.Cidr

/**
 * What to do with the routes the server pushed.
 */
@Serializable
enum class SplitTunnelMode {
    /** Hand the server configuration to the tunnel unchanged. The default. */
    @SerialName("off")
    OFF,

    /** Only [SplitTunnelSettings.routes] go through the tunnel. */
    @SerialName("include_only")
    INCLUDE_ONLY,

    /** Everything except [SplitTunnelSettings.routes] goes through the tunnel. */
    @SerialName("exclude")
    EXCLUDE,
}

/**
 * What to do with the applications the user listed.
 */
@Serializable
enum class SplitTunnelAppMode {
    /** The listed applications skip the VPN. */
    @SerialName("bypass")
    BYPASS,

    /** Only the listed applications use the VPN. */
    @SerialName("only")
    ONLY,
}

/**
 * What to do with the DNS servers the server pushed.
 */
@Serializable
enum class SplitTunnelDnsMode {
    /** Resolve every query with the pushed DNS servers. */
    @SerialName("server")
    SERVER,

    /** Resolve only the pushed search domains with the pushed DNS servers. */
    @SerialName("split")
    SPLIT,

    /** Drop the pushed DNS servers and keep using the system resolver. */
    @SerialName("system")
    SYSTEM,
}

/**
 * Client-side split tunneling settings for a single server.
 *
 * These settings are stored per server (keyed by the server base URL) and are applied to every
 * configuration the server hands out, including configurations fetched again after an expiry or
 * authorization refresh. They are never written back into the configuration cache.
 */
@Serializable
data class SplitTunnelSettings(
    @SerialName("schema_version")
    val schemaVersion: Int = SCHEMA_VERSION,

    val mode: SplitTunnelMode = SplitTunnelMode.OFF,

    /** IPv4 and IPv6 networks in CIDR notation. */
    val routes: List<String> = emptyList(),

    /** Android package names. */
    val apps: List<String> = emptyList(),

    @SerialName("app_mode")
    val appMode: SplitTunnelAppMode = SplitTunnelAppMode.BYPASS,

    val dns: SplitTunnelDnsMode = SplitTunnelDnsMode.SPLIT,

    /**
     * Keep the interface address prefixes routed through the tunnel and keep the peer endpoint
     * reachable outside of it, whatever the user entered.
     */
    @SerialName("always_include_tunnel_subnet")
    val alwaysIncludeTunnelSubnet: Boolean = true,

    /** Whether the user confirmed the default-gateway policy warning for this server. */
    @SerialName("policy_warning_acknowledged")
    val policyWarningAcknowledged: Boolean = false,
) {
    /** `true` when the server configuration must be rewritten before it reaches the tunnel. */
    val isActive: Boolean
        get() = mode != SplitTunnelMode.OFF ||
            apps.isNotEmpty() ||
            dns == SplitTunnelDnsMode.SYSTEM

    /** The configured routes, with invalid entries dropped. */
    fun parsedRoutes(): List<Cidr> = routes.mapNotNull(Cidr::parse)

    companion object {
        /**
         * Version of the stored representation.
         *
         * Bump this whenever the meaning of an existing field changes, and handle the old value in
         * [nl.eduvpn.app.service.SplitTunnelRepository.migrate].
         */
        const val SCHEMA_VERSION = 1

        /** Upper bound on the number of routes a user may configure for one server. */
        const val MAX_ROUTES = 256

        /** Upper bound on the number of applications a user may list for one server. */
        const val MAX_APPS = 512

        val OFF = SplitTunnelSettings()

        /**
         * Validates a single route as typed by the user.
         *
         * @return the canonical prefix, or `null` when the entry is not a usable route.
         */
        fun validateRoute(text: String): Cidr? {
            val cidr = Cidr.parse(text) ?: return null
            // A default route is not a split tunnel: it would either capture everything
            // (INCLUDE_ONLY) or disable the tunnel entirely (EXCLUDE).
            return if (cidr.isDefaultRoute) null else cidr
        }
    }
}
