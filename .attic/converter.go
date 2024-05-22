package asn2pf

import "inet.af/netaddr"

// tailscale converter  [... the missing parts that did not make it into golang std net/netip lib merger] [why?]
func range2net_tailscale(s, e string) (prefix []byte) {
	netrange, err := netaddr.ParseIPRange(s + "-" + e)
	if err != nil {
		OutErr("SKIP - unable to parse range [" + s + "-" + e + "]")
		return
	}
	prefixes := netrange.Prefixes()
	for _, p := range prefixes {
		net, _ := p.MarshalText()
		prefix = append(prefix, net...)
		prefix = append(prefix, []byte(" ")...)
	}
	return
}
