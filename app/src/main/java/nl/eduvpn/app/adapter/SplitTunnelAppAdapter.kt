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

package nl.eduvpn.app.adapter

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import nl.eduvpn.app.R
import nl.eduvpn.app.viewmodel.SplitTunnelSettingsViewModel.AppEntry

/**
 * Lets the user pick the applications the split tunnel applies to.
 */
class SplitTunnelAppAdapter(
    private val onSelectionChanged: (packageName: String, selected: Boolean) -> Unit,
) : ListAdapter<SplitTunnelAppAdapter.Item, SplitTunnelAppAdapter.ViewHolder>(DIFF_CALLBACK) {

    data class Item(val app: AppEntry, val selected: Boolean)

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val checkBox: CheckBox = view.findViewById(R.id.app_checkbox)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder = ViewHolder(
        LayoutInflater.from(parent.context)
            .inflate(R.layout.list_item_split_tunnel_app, parent, false)
    )

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = getItem(position)
        // Detach the listener first: the recycled view still carries the previous row's listener,
        // and setChecked() would report that row's package as toggled.
        holder.checkBox.setOnCheckedChangeListener(null)
        holder.checkBox.text = item.app.label
        holder.checkBox.isChecked = item.selected
        holder.checkBox.setOnCheckedChangeListener { _, isChecked ->
            onSelectionChanged(item.app.packageName, isChecked)
        }
    }

    companion object {
        private val DIFF_CALLBACK = object : DiffUtil.ItemCallback<Item>() {
            override fun areItemsTheSame(oldItem: Item, newItem: Item) =
                oldItem.app.packageName == newItem.app.packageName

            override fun areContentsTheSame(oldItem: Item, newItem: Item) = oldItem == newItem
        }
    }
}
