package asn2pf

import "inet.af/netaddr"

// tailscale converter  [... the missing parts that did not make it into golang std net/netip lib merger] [why?]
func range2net_tailscale(s, e string) []netaddr.IPPrefix {
	netrange, err := netaddr.ParseIPRange(s + "-" + e)
	if err != nil {
		OutErr("SKIP - unable to parse range [" + s + "-" + e + "]")
		return []netaddr.IPPrefix{}
	}
	return netrange.Prefixes()
}
