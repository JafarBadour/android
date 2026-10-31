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
package nl.eduvpn.app.fragment

import android.os.Bundle
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import androidx.appcompat.app.AlertDialog
import androidx.core.view.isVisible
import androidx.core.widget.doAfterTextChanged
import androidx.fragment.app.viewModels
import androidx.recyclerview.widget.LinearLayoutManager
import com.google.android.material.snackbar.Snackbar
import nl.eduvpn.app.EduVPNApplication
import nl.eduvpn.app.R
import nl.eduvpn.app.SettingsActivity
import nl.eduvpn.app.adapter.SplitTunnelAppAdapter
import nl.eduvpn.app.adapter.SplitTunnelRouteAdapter
import nl.eduvpn.app.base.BaseFragment
import nl.eduvpn.app.databinding.FragmentSplitTunnelSettingsBinding
import nl.eduvpn.app.entity.SplitTunnelAppMode
import nl.eduvpn.app.entity.SplitTunnelDnsMode
import nl.eduvpn.app.entity.SplitTunnelMode
import nl.eduvpn.app.entity.SplitTunnelSettings
import nl.eduvpn.app.viewmodel.SplitTunnelSettingsViewModel

/**
 * Lets the user configure client-side split tunneling for one of their servers.
 */
class SplitTunnelSettingsFragment : BaseFragment<FragmentSplitTunnelSettingsBinding>() {

    private val viewModel by viewModels<SplitTunnelSettingsViewModel> { viewModelFactory }

    override val layout = R.layout.fragment_split_tunnel_settings

    private lateinit var routeAdapter: SplitTunnelRouteAdapter
    private lateinit var appAdapter: SplitTunnelAppAdapter

    /** Set while the view model is driving the controls, so listeners do not echo back. */
    private var isBinding = false

    private var appFilter: String = ""

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        EduVPNApplication.get(view.context).component().inject(this)

        if (viewModel.servers.isEmpty()) {
            binding.noServers.isVisible = true
            binding.settingsContainer.isVisible = false
            return
        }

        setUpServerSpinner()
        setUpRouteList()
        setUpAppList()
        setUpModeControls()

        binding.saveButton.setOnClickListener { viewModel.save() }

        viewModel.settings.observe(viewLifecycleOwner) { render(it) }
        viewModel.routeError.observe(viewLifecycleOwner) { binding.routeError.isVisible = it }
        viewModel.installedApps.observe(viewLifecycleOwner) { submitAppList() }
        viewModel.action.observe(viewLifecycleOwner) { onAction(it) }
    }

    private fun setUpServerSpinner() {
        val names = viewModel.servers.map {
            it.displayName.bestTranslation ?: it.sanitizedBaseURI
        }
        val adapter = ArrayAdapter(
            requireContext(),
            android.R.layout.simple_spinner_item,
            names
        )
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        binding.serverSpinner.adapter = adapter
        viewModel.selectedServer.value?.let { selected ->
            val index = viewModel.servers.indexOfFirst { it.baseURI == selected.baseURI }
            if (index >= 0) {
                binding.serverSpinner.setSelection(index)
            }
        }
        binding.serverSpinner.onItemSelectedListener =
            object : AdapterView.OnItemSelectedListener {
                override fun onItemSelected(
                    parent: AdapterView<*>?,
                    view: View?,
                    position: Int,
                    id: Long,
                ) {
                    viewModel.servers.getOrNull(position)?.let { viewModel.selectServer(it) }
                }

                override fun onNothingSelected(parent: AdapterView<*>?) = Unit
            }
    }

    private fun setUpRouteList() {
        routeAdapter = SplitTunnelRouteAdapter { viewModel.removeRoute(it) }
        binding.routeList.layoutManager = LinearLayoutManager(requireContext())
        binding.routeList.adapter = routeAdapter
        binding.addRouteButton.setOnClickListener {
            if (viewModel.addRoute(binding.routeInput.text.toString())) {
                binding.routeInput.setText("")
            }
        }
    }

    private fun setUpAppList() {
        appAdapter = SplitTunnelAppAdapter { packageName, selected ->
            if (!isBinding) {
                viewModel.setAppSelected(packageName, selected)
            }
        }
        binding.appList.layoutManager = LinearLayoutManager(requireContext())
        binding.appList.adapter = appAdapter
        binding.appSearch.doAfterTextChanged {
            appFilter = it?.toString()?.trim()?.lowercase() ?: ""
            submitAppList()
        }
    }

    private fun setUpModeControls() {
        binding.modeGroup.setOnCheckedChangeListener { _, checkedId ->
            if (isBinding) {
                return@setOnCheckedChangeListener
            }
            viewModel.setMode(
                when (checkedId) {
                    R.id.mode_include_only -> SplitTunnelMode.INCLUDE_ONLY
                    R.id.mode_exclude -> SplitTunnelMode.EXCLUDE
                    else -> SplitTunnelMode.OFF
                }
            )
        }
        binding.dnsGroup.setOnCheckedChangeListener { _, checkedId ->
            if (isBinding) {
                return@setOnCheckedChangeListener
            }
            viewModel.setDnsMode(
                when (checkedId) {
                    R.id.dns_server -> SplitTunnelDnsMode.SERVER
                    R.id.dns_system -> SplitTunnelDnsMode.SYSTEM
                    else -> SplitTunnelDnsMode.SPLIT
                }
            )
        }
        binding.appModeGroup.setOnCheckedChangeListener { _, checkedId ->
            if (isBinding) {
                return@setOnCheckedChangeListener
            }
            viewModel.setAppMode(
                if (checkedId == R.id.app_mode_only) {
                    SplitTunnelAppMode.ONLY
                } else {
                    SplitTunnelAppMode.BYPASS
                }
            )
        }
    }

    private fun render(settings: SplitTunnelSettings) {
        isBinding = true
        try {
            binding.modeGroup.check(
                when (settings.mode) {
                    SplitTunnelMode.OFF -> R.id.mode_off
                    SplitTunnelMode.INCLUDE_ONLY -> R.id.mode_include_only
                    SplitTunnelMode.EXCLUDE -> R.id.mode_exclude
                }
            )
            binding.dnsGroup.check(
                when (settings.dns) {
                    SplitTunnelDnsMode.SERVER -> R.id.dns_server
                    SplitTunnelDnsMode.SPLIT -> R.id.dns_split
                    SplitTunnelDnsMode.SYSTEM -> R.id.dns_system
                }
            )
            binding.appModeGroup.check(
                when (settings.appMode) {
                    SplitTunnelAppMode.BYPASS -> R.id.app_mode_bypass
                    SplitTunnelAppMode.ONLY -> R.id.app_mode_only
                }
            )
            binding.routesContainer.isVisible = settings.mode != SplitTunnelMode.OFF
            binding.defaultGatewayWarning.isVisible = viewModel.isDefaultGateway
            routeAdapter.submitList(settings.routes)
            submitAppList()
        } finally {
            isBinding = false
        }
    }

    private fun submitAppList() {
        val selected = viewModel.settings.value?.apps.orEmpty().toSet()
        val apps = viewModel.installedApps.value.orEmpty()
            .filter { appFilter.isEmpty() || it.label.lowercase().contains(appFilter) }
            .map { SplitTunnelAppAdapter.Item(it, it.packageName in selected) }
        appAdapter.submitList(apps)
    }

    private fun onAction(action: SplitTunnelSettingsViewModel.Action) {
        when (action) {
            is SplitTunnelSettingsViewModel.Action.ConfirmPolicyWarning -> {
                AlertDialog.Builder(requireContext())
                    .setTitle(R.string.split_tunnel_policy_warning_title)
                    .setMessage(
                        getString(
                            R.string.split_tunnel_policy_warning_message,
                            action.serverName
                        )
                    )
                    .setPositiveButton(R.string.split_tunnel_policy_warning_accept) { dialog, _ ->
                        dialog.dismiss()
                        viewModel.acknowledgePolicyWarning()
                    }
                    .setNegativeButton(R.string.split_tunnel_policy_warning_decline) { dialog, _ ->
                        dialog.dismiss()
                        viewModel.declinePolicyWarning()
                    }
                    .setCancelable(false)
                    .show()
            }

            SplitTunnelSettingsViewModel.Action.OfferReconnect -> {
                Snackbar.make(
                    binding.root,
                    R.string.split_tunnel_reconnect_needed,
                    Snackbar.LENGTH_INDEFINITE
                ).setAction(R.string.split_tunnel_reconnect_action) {
                    requireActivity().setResult(SettingsActivity.RESULT_SPLIT_TUNNEL_RECONNECT)
                    requireActivity().finish()
                }.show()
            }

            SplitTunnelSettingsViewModel.Action.Saved -> {
                Snackbar.make(
                    binding.root,
                    R.string.split_tunnel_saved,
                    Snackbar.LENGTH_SHORT
                ).show()
            }
        }
    }
}
