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
import android.widget.Button
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import nl.eduvpn.app.R

/**
 * Shows the networks the user listed for split tunneling, with a button to drop each one.
 */
class SplitTunnelRouteAdapter(
    private val onRemoveClicked: (route: String) -> Unit,
) : ListAdapter<String, SplitTunnelRouteAdapter.ViewHolder>(DIFF_CALLBACK) {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val route: TextView = view.findViewById(R.id.route)
        val removeButton: Button = view.findViewById(R.id.remove_route_button)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder = ViewHolder(
        LayoutInflater.from(parent.context)
            .inflate(R.layout.list_item_split_tunnel_route, parent, false)
    )

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val route = getItem(position)
        holder.route.text = route
        holder.removeButton.contentDescription = holder.itemView.context.getString(
            R.string.split_tunnel_remove_route_description, route
        )
        holder.removeButton.setOnClickListener { onRemoveClicked(route) }
    }

    companion object {
        private val DIFF_CALLBACK = object : DiffUtil.ItemCallback<String>() {
            override fun areItemsTheSame(oldItem: String, newItem: String) = oldItem == newItem
            override fun areContentsTheSame(oldItem: String, newItem: String) = oldItem == newItem
        }
    }
}
