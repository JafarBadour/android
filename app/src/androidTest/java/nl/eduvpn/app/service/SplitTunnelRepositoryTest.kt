/*
 *  This file is part of eduVPN.
 *
 *     eduVPN is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     eduVPN is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with eduVPN.  If not, see <http://www.gnu.org/licenses/>.
 */
package nl.eduvpn.app.service

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import com.wireguard.config.Config
import nl.eduvpn.app.entity.SplitTunnelAppMode
import nl.eduvpn.app.entity.SplitTunnelDnsMode
import nl.eduvpn.app.entity.SplitTunnelMode
import nl.eduvpn.app.entity.SplitTunnelSettings
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.BufferedReader
import java.io.StringReader

/**
 * Tests the storage and the migration of the split tunneling settings, and smoke-tests the
 * rewriter against the real WireGuard library on a device.
 */
@RunWith(AndroidJUnit4::class)
@LargeTest
class SplitTunnelRepositoryTest {

    private lateinit var preferencesService: PreferencesService
    private lateinit var repository: SplitTunnelRepository

    private val serverId = "https://vpn.example.org/"

    @Before
    fun before() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        preferencesService = PreferencesService(context, SerializerService())
        repository = SplitTunnelRepository(preferencesService)
        repository.remove(serverId)
    }

    @Test
    fun unknownServerIsOff() {
        Assert.assertEquals(
            SplitTunnelSettings.OFF,
            repository.get("https://never-configured.example.org/")
        )
    }

    @Test
    fun settingsSurviveARoundTrip() {
        val settings = SplitTunnelSettings(
            mode = SplitTunnelMode.EXCLUDE,
            routes = listOf("192.168.0.0/16", "2001:db8::/32"),
            apps = listOf("org.mozilla.firefox"),
            appMode = SplitTunnelAppMode.BYPASS,
            dns = SplitTunnelDnsMode.SYSTEM,
            policyWarningAcknowledged = true,
        )
        repository.save(serverId, settings)

        // A fresh repository reads the same values back, which is what happens after a restart.
        val reloaded = SplitTunnelRepository(preferencesService).get(serverId)
        Assert.assertEquals(settings, reloaded)
    }

    @Test
    fun invalidAndDuplicateRoutesAreDropped() {
        repository.save(
            serverId,
            SplitTunnelSettings(
                mode = SplitTunnelMode.INCLUDE_ONLY,
                // Invalid, a default route, a duplicate and a non-canonical spelling.
                routes = listOf(
                    "10.0.0.0/8", "nonsense", "0.0.0.0/0", "10.0.0.0/8", "10.1.2.3/8"
                ),
                apps = listOf("org.mozilla.firefox", "org.mozilla.firefox", " "),
            )
        )
        val stored = repository.get(serverId)
        Assert.assertEquals(listOf("10.0.0.0/8"), stored.routes)
        Assert.assertEquals(listOf("org.mozilla.firefox"), stored.apps)
    }

    @Test
    fun routeListIsCapped() {
        val tooMany = (0 until SplitTunnelSettings.MAX_ROUTES + 10).map { "10.$it.0.0/16" }
        repository.save(
            serverId,
            SplitTunnelSettings(mode = SplitTunnelMode.INCLUDE_ONLY, routes = tooMany)
        )
        Assert.assertEquals(
            SplitTunnelSettings.MAX_ROUTES,
            repository.get(serverId).routes.size
        )
    }

    @Test
    fun settingsFromANewerSchemaAreIgnored() {
        preferencesService.setSplitTunnelSettings(
            serverId,
            SplitTunnelSettings(
                schemaVersion = SplitTunnelSettings.SCHEMA_VERSION + 1,
                mode = SplitTunnelMode.EXCLUDE,
                routes = listOf("192.168.0.0/16"),
            )
        )
        Assert.assertEquals(SplitTunnelSettings.OFF, repository.get(serverId))
    }

    @Test
    fun corruptedSettingsAreIgnored() {
        preferencesService.getSharedPreferences().edit()
            .putString("split_tunnel_$serverId", "{ this is not json")
            .commit()
        Assert.assertEquals(SplitTunnelSettings.OFF, repository.get(serverId))
    }

    @Test
    fun removeForgetsTheSettings() {
        repository.save(
            serverId,
            SplitTunnelSettings(mode = SplitTunnelMode.EXCLUDE, routes = listOf("10.0.0.0/8"))
        )
        repository.remove(serverId)
        Assert.assertEquals(SplitTunnelSettings.OFF, repository.get(serverId))
    }

    /**
     * Smoke test against the real WireGuard library: the rewritten configuration must still parse
     * and must carry exactly the expected `AllowedIPs`.
     */
    @Test
    fun rewrittenWireGuardConfigKeepsOnlyTheIncludedRoutes() {
        val config = Config.parse(
            BufferedReader(
                StringReader(
                    """
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
                    """.trimIndent()
                )
            )
        )
        val rewritten = SplitTunnelRewriter.rewrite(
            config,
            SplitTunnelSettings(
                mode = SplitTunnelMode.INCLUDE_ONLY,
                routes = listOf("10.0.0.0/8", "130.89.0.0/16"),
                apps = listOf("org.mozilla.firefox"),
            ),
            isDefaultGateway = true,
        )
        Assert.assertEquals(
            listOf("10.0.0.0/8", "130.89.0.0/16", "fd43::/112"),
            rewritten.peers.single().allowedIps.map { it.toString() }
        )
        Assert.assertEquals(
            setOf("org.mozilla.firefox"),
            rewritten.`interface`.excludedApplications
        )
        // The result has to survive a round trip through the wg-quick format the backend uses.
        val reparsed = Config.parse(
            BufferedReader(StringReader(rewritten.toWgQuickString()))
        )
        Assert.assertEquals(
            rewritten.peers.single().allowedIps,
            reparsed.peers.single().allowedIps
        )
    }
}
