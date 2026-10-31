/*
 * This file is part of eduVPN.
 *
 * eduVPN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * eduVPN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with eduVPN.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package nl.eduvpn.app.viewmodel

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import nl.eduvpn.app.entity.Instance
import nl.eduvpn.app.entity.SplitTunnelAppMode
import nl.eduvpn.app.entity.SplitTunnelDnsMode
import nl.eduvpn.app.entity.SplitTunnelMode
import nl.eduvpn.app.entity.SplitTunnelSettings
import nl.eduvpn.app.service.HistoryService
import nl.eduvpn.app.service.PreferencesService
import nl.eduvpn.app.service.SplitTunnelRepository
import nl.eduvpn.app.service.VPNService
import nl.eduvpn.app.utils.toSingleEvent
import java.util.Optional
import javax.inject.Inject

/**
 * Backs the split tunneling settings screen.
 *
 * The screen edits the settings of exactly one server at a time; the user picks which one. Edits
 * are kept in memory until they are saved, so leaving the screen discards them.
 */
class SplitTunnelSettingsViewModel @Inject constructor(
    private val context: Context,
    private val historyService: HistoryService,
    private val preferencesService: PreferencesService,
    private val splitTunnelRepository: SplitTunnelRepository,
    private val vpnService: Optional<VPNService>,
) : ViewModel() {

    /** One installed application the user may add to the list. */
    data class AppEntry(val packageName: String, val label: String)

    /** Something the fragment has to show the user. */
    sealed class Action {
        /** The user enabled a non-OFF mode on a default-gateway server for the first time. */
        data class ConfirmPolicyWarning(val serverName: String) : Action()

        /** Settings were saved while this very server is connected. */
        data object OfferReconnect : Action()

        /** Settings were saved and no reconnect is needed. */
        data object Saved : Action()
    }

    /** Every server the user added, in the order they are shown in the list. */
    val servers: List<Instance> = buildServerList()

    private val _selectedServer = MutableLiveData<Instance?>(preselectedServer())
    val selectedServer: LiveData<Instance?> = _selectedServer

    private val _settings = MutableLiveData(SplitTunnelSettings.OFF)
    val settings: LiveData<SplitTunnelSettings> = _settings

    private val _routeError = MutableLiveData<Boolean>(false)
    val routeError: LiveData<Boolean> = _routeError

    private val _installedApps = MutableLiveData<List<AppEntry>>(emptyList())
    val installedApps: LiveData<List<AppEntry>> = _installedApps

    private val _action = MutableLiveData<Action>()
    val action = _action.toSingleEvent()

    /**
     * Whether the selected server handed out a default-gateway profile the last time we connected.
     *
     * The flag only reaches the client together with a configuration, so it is remembered per
     * server when a configuration arrives. A server we have never connected to is assumed to be
     * default-gateway: every eduVPN profile routes everything unless the administrator says
     * otherwise, and warning needlessly is better than staying silent about a policy violation.
     */
    val isDefaultGateway: Boolean
        get() = _selectedServer.value
            ?.let { preferencesService.getLastDefaultGateway(it.baseURI) }
            ?: true

    init {
        _selectedServer.value?.let { loadSettingsFor(it) }
        loadInstalledApps()
    }

    /** A name for the selected server which is safe to show to the user. */
    fun selectedServerName(): String {
        val instance = _selectedServer.value ?: return ""
        return instance.displayName.bestTranslation ?: instance.sanitizedBaseURI
    }

    fun selectServer(instance: Instance) {
        _selectedServer.value = instance
        loadSettingsFor(instance)
    }

    private fun loadSettingsFor(instance: Instance) {
        _settings.value = splitTunnelRepository.get(instance.baseURI)
        _routeError.value = false
    }

    /**
     * Changes the mode.
     *
     * Switching away from [SplitTunnelMode.OFF] on a default-gateway profile needs the policy
     * warning to be acknowledged once per server.
     */
    fun setMode(mode: SplitTunnelMode) {
        val current = _settings.value ?: return
        if (current.mode == mode) {
            return
        }
        _settings.value = current.copy(mode = mode)
        if (mode != SplitTunnelMode.OFF && !current.policyWarningAcknowledged && isDefaultGateway) {
            _action.value = Action.ConfirmPolicyWarning(selectedServerName())
        }
    }

    /** Records that the user confirmed the policy warning for the selected server. */
    fun acknowledgePolicyWarning() {
        val current = _settings.value ?: return
        _settings.value = current.copy(policyWarningAcknowledged = true)
    }

    /** Reverts to [SplitTunnelMode.OFF] after the user declined the policy warning. */
    fun declinePolicyWarning() {
        val current = _settings.value ?: return
        _settings.value = current.copy(mode = SplitTunnelMode.OFF)
    }

    fun setDnsMode(dns: SplitTunnelDnsMode) {
        _settings.value = (_settings.value ?: return).copy(dns = dns)
    }

    fun setAppMode(appMode: SplitTunnelAppMode) {
        _settings.value = (_settings.value ?: return).copy(appMode = appMode)
    }

    /**
     * Adds a route as typed by the user.
     *
     * @return `true` when the entry was a usable network and was added.
     */
    fun addRoute(text: String): Boolean {
        val current = _settings.value ?: return false
        val route = SplitTunnelSettings.validateRoute(text)
        if (route == null || current.routes.size >= SplitTunnelSettings.MAX_ROUTES) {
            _routeError.value = true
            return false
        }
        _routeError.value = false
        val canonical = route.toString()
        if (canonical in current.routes) {
            return true
        }
        _settings.value = current.copy(routes = current.routes + canonical)
        return true
    }

    fun removeRoute(route: String) {
        val current = _settings.value ?: return
        _settings.value = current.copy(routes = current.routes - route)
    }

    fun setAppSelected(packageName: String, selected: Boolean) {
        val current = _settings.value ?: return
        val apps = when {
            selected && current.apps.size >= SplitTunnelSettings.MAX_APPS -> return
            selected -> current.apps + packageName
            else -> current.apps - packageName
        }
        _settings.value = current.copy(apps = apps.distinct())
    }

    /** Saves the settings of the selected server and tells the fragment what to show next. */
    fun save() {
        val instance = _selectedServer.value ?: return
        val settings = _settings.value ?: return
        splitTunnelRepository.save(instance.baseURI, settings)
        // Re-read so the screen shows exactly what was stored, including dropped entries.
        _settings.value = splitTunnelRepository.get(instance.baseURI)
        _action.value =
            if (isConnectedTo(instance)) Action.OfferReconnect else Action.Saved
    }

    private fun isConnectedTo(instance: Instance): Boolean {
        val service = vpnService.orElse(null) ?: return false
        if (service.getStatus() == VPNService.VPNStatus.DISCONNECTED) {
            return false
        }
        return preferencesService.getCurrentInstance()?.baseURI == instance.baseURI
    }

    private fun buildServerList(): List<Instance> =
        historyService.addedServers?.asInstances() ?: emptyList()

    private fun preselectedServer(): Instance? {
        val currentBaseUri = preferencesService.getCurrentInstance()?.baseURI
        return servers.firstOrNull { it.baseURI == currentBaseUri } ?: servers.firstOrNull()
    }

    @Suppress("DEPRECATION")
    private fun loadInstalledApps() {
        viewModelScope.launch {
            val apps = withContext(Dispatchers.IO) {
                val packageManager = context.packageManager
                packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
                    .asSequence()
                    // Applications without internet access cannot leak anything either way.
                    .filter { it.packageName != context.packageName }
                    .filter { hasInternetPermission(packageManager, it) }
                    .map {
                        AppEntry(
                            it.packageName,
                            packageManager.getApplicationLabel(it).toString()
                        )
                    }
                    .sortedBy { it.label.lowercase() }
                    .toList()
            }
            _installedApps.value = apps
        }
    }

    private fun hasInternetPermission(
        packageManager: PackageManager,
        applicationInfo: ApplicationInfo,
    ): Boolean = packageManager.checkPermission(
        android.Manifest.permission.INTERNET,
        applicationInfo.packageName
    ) == PackageManager.PERMISSION_GRANTED
}
