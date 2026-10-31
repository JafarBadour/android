# Split tunneling

Split tunneling lets you decide which traffic goes through the VPN. It is a **client-side**
feature: the server keeps handing out its normal configuration, and the app rewrites what it
passes to the tunnel.

It is **off by default** for every server. When it is off, the configuration reaches the tunnel
exactly as the server wrote it.

> **Your institution may not allow this.** Most eduVPN profiles are configured to route *all*
> traffic through the VPN, and overriding that may violate your institution's policy. Traffic you
> exclude is no longer protected by the VPN. The app warns you once per server before you switch
> the feature on.

## Where to find it

**Settings → Split tunneling → Configure.** The screen edits one server at a time; pick it from
the *Server* list at the top. Settings are stored per server and survive app restarts, session
expiry, re-authorization and a protocol failover from WireGuard to OpenVPN.

Changing settings while you are connected to that server does not take effect immediately. The
app offers a *Reconnect* action; after reconnecting the new routes are live.

## Modes

| Mode | What goes through the VPN |
| --- | --- |
| **Off** (default) | Whatever the server configured. |
| **Only send the networks below** | Only the networks you list. |
| **Send everything except the networks below** | Everything except the networks you list. |

Networks are entered in CIDR notation, IPv4 or IPv6 — for example `10.0.0.0/8`,
`130.89.0.0/16`, `2001:db8::/32`. A single address such as `145.100.1.1` is accepted and treated
as a `/32` (or `/128`).

A network covering every address (`0.0.0.0/0`, `::/0`) is rejected: it is not a split tunnel, it
either captures everything or disables the tunnel entirely.

### IPv4 and IPv6 are independent

The two address families are handled completely separately. If you only list IPv4 networks, **all
IPv6 traffic keeps using the VPN**, and vice versa. To exclude a dual-stack destination you have
to list both its IPv4 and its IPv6 prefix.

### Profiles that are not full-tunnel

Servers tell the client whether a profile routes everything (`default_gateway`). When a profile
already pushes only a partial route set:

- **Only send the networks below** *narrows* that set rather than widening it. With WireGuard the
  client intersects your list with the pushed routes, so a network the server does not route is
  not routed. With OpenVPN the pushed routes are dropped and your list is installed instead, which
  the client cannot intersect because it does not know the pushed routes at the time the
  configuration is written — a destination the server does not route then becomes unreachable
  rather than leaking.
- **Send everything except the networks below** subtracts your list from the pushed routes.

## Per-app split tunneling

Independently of the route lists you can pick applications:

| Mode | Effect |
| --- | --- |
| **The apps below skip the VPN** | The listed apps use the normal network; everything else uses the VPN. |
| **Only the apps below use the VPN** | Only the listed apps use the VPN. |

The app list shows launchable installed applications that hold the `INTERNET` permission; eduVPN
itself is never listed. Per-app routing is enforced by Android itself (`VpnService.Builder`), so it
applies to both WireGuard and OpenVPN.

Leaving the list empty means the setting does nothing, whichever mode is selected.

On Android 11 and later, package visibility is filtered. The manifest declares a `<queries>`
element for the launcher intent instead of asking for `QUERY_ALL_PACKAGES`, so apps without a
launcher entry — background services, for instance — are not offered in the picker. Apps already
stored in the list keep working even if they are not visible in the picker.

## DNS

| Setting | WireGuard | OpenVPN |
| --- | --- | --- |
| **Use the DNS servers of the VPN for everything** | Pushed resolvers are kept. | Pushed resolvers are kept. |
| **Use the DNS servers of the VPN for its own domains only** (default when a mode is active) | Pushed resolvers and search domains are kept. | Pushed resolvers and `dhcp-option DOMAIN` are kept. |
| **Keep using the DNS servers of this device** | Pushed resolvers and search domains are dropped. | `pull-filter ignore "dhcp-option DNS"` is added. |

**Android platform rule:** a VPN that does not claim a default route only receives DNS queries for
its search domains. So as soon as split tunneling is active, *Use the DNS servers of the VPN for
everything* behaves like *…for its own domains only*. The app cannot override this, and says so in
the hint under the selector.

If the server pushes no search domains at all, split DNS cannot be expressed and all queries go to
the system resolver.

## What is always protected

Whatever you enter, the following stay intact (`alwaysIncludeTunnelSubnet`, on by default):

- the **interface address prefixes** of the tunnel stay routed through the tunnel, so the tunnel's
  own subnet remains reachable;
- the **peer endpoint** is carved out of the tunnel, so the tunnel can still reach its own server;
- the **ProxyGuard** listener and the keys, endpoint, keep-alive and MTU of the configuration are
  never touched.

## How it is implemented

One platform-neutral model and one pure rewrite per protocol, applied between the point where
`eduvpn-common` hands over the finished configuration and the point where the tunnel is started:

| Piece | File |
| --- | --- |
| Settings model | `app/src/main/java/nl/eduvpn/app/entity/SplitTunnelSettings.kt` |
| CIDR set arithmetic | `app/src/main/java/nl/eduvpn/app/utils/CidrMath.kt` |
| Rewriter | `app/src/main/java/nl/eduvpn/app/service/SplitTunnelRewriter.kt` |
| Storage | `app/src/main/java/nl/eduvpn/app/service/SplitTunnelRepository.kt` |
| Hook point | `app/src/main/java/nl/eduvpn/app/viewmodel/MainViewModel.kt` |
| UI | `app/src/main/java/nl/eduvpn/app/fragment/SplitTunnelSettingsFragment.kt` |

The rewriter is a pure function of (server configuration, settings, `default_gateway`) and keeps no
state, so it is re-applied to every configuration the server hands out. Rewritten configurations
are never written back into the configuration cache.

### WireGuard

`AllowedIPs` is recomputed per peer. WireGuard has no exclude syntax, so *Send everything except…*
is implemented as a CIDR complement: the excluded networks are subtracted from the original
`AllowedIPs` and the minimal covering prefix list is emitted, per address family. Application
lists become `IncludedApplications` / `ExcludedApplications` on the interface, which
`GoBackend` turns into `VpnService.Builder.addAllowedApplication()` /
`addDisallowedApplication()`.

### OpenVPN

ics-openvpn regenerates the OpenVPN configuration from a parsed `VpnProfile` rather than passing
the server's text through, so the directives are appended to `VpnProfile.mCustomConfigOptions`,
which `VpnProfile.getConfigFile()` emits verbatim at the end of the generated configuration.
Writing them there (rather than setting `mCustomRoutes` / `mExcludedRoutes`) keeps one code path
for both modes — `mExcludedRoutes` is only emitted when the profile does not use a default route —
and keeps the generated text identical to what the Windows client writes. Application lists are
set on `VpnProfile.mAllowedAppsVpn` / `mAllowedAppsVpnAreDisallowed`.

*Only send the networks below* emits:

```
pull-filter ignore "redirect-gateway"
pull-filter ignore "redirect-private"
pull-filter ignore "route "
pull-filter ignore "route-ipv6 "
route <net> <mask> vpn_gateway
route-ipv6 <prefix>
```

The trailing space in `"route "` is deliberate: it keeps pushed `route-gateway` and `route-metric`
options. `route-nopull` is deliberately *not* used — from OpenVPN 2.5 on it also drops the pushed
DNS options, which the DNS setting controls separately.

*Send everything except the networks below* emits:

```
redirect-gateway def1 ipv6
route <net> <mask> net_gateway
route-ipv6 <prefix> net_gateway
```

ics-openvpn turns `net_gateway` routes into exclusions on its own `NetworkSpace`, which performs
real set subtraction, so the resulting route set is exact regardless of prefix lengths.

## Settings schema

Stored in the app's encrypted shared preferences under `split_tunnel_<server base URL>`:

```jsonc
{
  "schema_version": 1,
  "mode": "off" | "include_only" | "exclude",
  "routes": ["10.0.0.0/8", "2001:db8::/32"],
  "apps": ["org.mozilla.firefox"],
  "app_mode": "bypass" | "only",
  "dns": "server" | "split" | "system",
  "always_include_tunnel_subnet": true,
  "policy_warning_acknowledged": false
}
```

A missing entry means *Off*. Entries written by a newer schema version than the client understands
are ignored rather than guessed at. Invalid routes are dropped on read and on write; the route list
is capped at 256 entries and the application list at 512.

## Known limitations

- **Android decides DNS scoping.** See the platform rule above: on a split tunnel the client cannot
  force all queries to the pushed resolvers.
- **No split DNS without search domains.** If the server pushes resolvers but no search domains,
  the *…for its own domains only* setting falls back to the system resolver for everything.
- **OpenVPN cannot intersect unknown pushed routes.** See *Profiles that are not full-tunnel*.
- **A hostname endpoint is not carved out.** The peer endpoint is only excluded from the tunnel
  when it is given as a literal address. With a hostname the carve-out is skipped; on Android this
  is harmless because `GoBackend` protects the tunnel socket, and OpenVPN keeps a host route to its
  own server.
- **Per-app routing is Android-only.** The Windows client has route-based split tunneling only.
- **The app picker only lists launchable apps.** See *Per-app split tunneling*.
- **No per-profile settings.** Settings are per server, not per profile within a server.
