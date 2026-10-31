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

import nl.eduvpn.app.entity.SplitTunnelSettings
import nl.eduvpn.app.utils.Log

/**
 * Stores the split tunneling settings of every server the user added.
 *
 * Settings are keyed by the server base URL and live next to the other per-server data in
 * [PreferencesService]. A server without an entry has split tunneling switched off.
 */
class SplitTunnelRepository(private val preferencesService: PreferencesService) {

    /** Returns the settings of a server, or [SplitTunnelSettings.OFF] when there are none. */
    fun get(serverId: String): SplitTunnelSettings =
        migrate(serverId, preferencesService.getSplitTunnelSettings(serverId))

    /**
     * Saves the settings of a server.
     *
     * Invalid routes are dropped and both lists are capped, so a corrupted or oversized entry can
     * never reach the rewriter.
     */
    fun save(serverId: String, settings: SplitTunnelSettings) {
        preferencesService.setSplitTunnelSettings(serverId, sanitize(settings))
    }

    /** Forgets the settings of a server, for instance when the user removes it. */
    fun remove(serverId: String) {
        preferencesService.removeSplitTunnelSettings(serverId)
    }

    /**
     * Brings a stored entry up to the current schema version.
     *
     * Version 1 is the first released schema, so there is nothing to convert yet; anything newer
     * than we understand is discarded rather than guessed at.
     */
    private fun migrate(serverId: String, settings: SplitTunnelSettings): SplitTunnelSettings {
        if (settings.schemaVersion == SplitTunnelSettings.SCHEMA_VERSION) {
            return sanitize(settings)
        }
        if (settings.schemaVersion > SplitTunnelSettings.SCHEMA_VERSION) {
            Log.w(
                TAG,
                "Split tunneling settings for $serverId use unknown schema version " +
                    "${settings.schemaVersion}, ignoring them."
            )
            return SplitTunnelSettings.OFF
        }
        // No released schema is older than the current one yet.
        return sanitize(settings.copy(schemaVersion = SplitTunnelSettings.SCHEMA_VERSION))
    }

    private fun sanitize(settings: SplitTunnelSettings): SplitTunnelSettings = settings.copy(
        routes = settings.routes
            .mapNotNull { SplitTunnelSettings.validateRoute(it)?.toString() }
            .distinct()
            .take(SplitTunnelSettings.MAX_ROUTES),
        apps = settings.apps
            .filter { it.isNotBlank() }
            .distinct()
            .take(SplitTunnelSettings.MAX_APPS),
    )

    companion object {
        private val TAG = SplitTunnelRepository::class.java.name
    }
}
