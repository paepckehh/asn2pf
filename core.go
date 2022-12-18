package asn2pf

import (
	"strconv"
	"strings"

	"paepcke.de/asn2pf/asnfetch"
)

// const mode
const (
	_none = iota
	_asn
	_owner
	_country
	_cacheUse
	_cacheRebuild
	_ownerPrefix
)

// const shortcuts
const (
	// HEADER
	_LF = "\n"
	_H1 = "#" + _LF
	_H2 = "# pf(4) ASN STATIC TABLES" + _LF
	_H3 = "# Do not edit manually! - This file is auto-generated via asn2pf " // + timestamp
	_H4 = "# please add to /etc/pf.conf -> include "                          // + filename
	_H5 = "# restart - to see stats: pfctl -vvsT" + _LF
)

// modeName ..
func modeName(in int) string {
	switch in {
	case _asn:
		return "asn"
	case _owner:
		return "owner"
	case _country:
		return "country"
	}
	panic("invalide mode type name")
}

// parseOptions ...
func parseOptions(in []string, tables []byte, src []asnfetch.Source) ([]query, string, string, int, []byte) {
	// filter rules & table options first, build rules and table options
	rules, all, all_names := false, false, ""
	table_opts, rule := "const persist", ""
	for i, term := range in {
		switch term {
		case "all":
			all = true
		case "match":
			rule = "match "
		case "block":
			rule = "block "
		case "drop":
			rule = "block drop "
		case "log":
			rule += "log "
		case "count", "counters":
			table_opts += " counters "
		case "download", "update":
			return []query{}, "", "", _none, tables
		case "rebuild", "rebuild_cache":
			return []query{}, "", "", _cacheRebuild, tables
		default:
			continue
		}
		in[i] = ""
	}
	if len(rule) > 5 && rule[:5] == "block" {
		rule += "quick "
	}
	if rule != "" {
		rules = true
	}

	// build query array
	querys := []query{}
	for _, term := range in {

		if term == "" {
			continue
		}
		mode, l := _none, len(term)
		// expand search shortcuts
		switch term {
		case "private", "rfc1918", "bougus", "bogus", "bogous", "martians", "notrouted", "notconnected":
			querys = append(querys, query{mode: _asn, term: "0"})
			continue
		case "DoD":
			querys = append(querys, query{mode: _ownerPrefix, term: "dnic-", name: "dod"})
			continue
		default:
			// search key sanitizer
			switch {
			case l > 4 && term[:4] == "asn:":
				if _, err := strconv.ParseUint(term[4:], 10, 0); err != nil {
					info("Skip invalid asn serch term: [" + term[4:] + "] [asn(s) are numbers only]")
				} else {
					mode, term = _asn, term[4:]
				}
			case l > 6 && term[:6] == "owner:":
				mode, term = _owner, strings.ToLower(term[6:])
			case l > 8 && term[:8] == "country:":
				mode, term = _country, term[8:]
				if term != "None" {
					term = strings.ToUpper(term)
				}
			}
		}

		// expand row-less search terms
		if l > 2 && mode == _none {
			mode, term = _owner, strings.ToLower(term)
		}

		// if mode is still empty, skip
		if mode == _none {
			info("SKIP: invalid search term [" + term + "] [3 characters are minimum]")
			continue
		}

		// add query to array
		querys = append(querys, query{
			mode: mode,
			term: term,
		},
		)

		// add table rule to table head for all sources
		for _, s := range src {
			tableSuffix := ""
			switch {
			case s.IPv4:
				tableSuffix += "_ip4"
			case s.IPv6:
				tableSuffix += "_ip6"
			}
			name := "<" + modeName(mode) + "_" + strings.ToLower(term) + tableSuffix + ">"
			if rules {
				inbound := []byte(rule + "from any to " + name + " \n")
				outbound := []byte(rule + "from " + name + " to any\n")
				tables = append(tables, append(inbound, outbound...)...)
			}
			if all {
				all_names = all_names + name + " "
			}
		}

	}

	if all {
		tables = append(tables, []byte("\ntable <all> const persist { "+all_names+"}\n")...)
	}
	return querys, table_opts, rule, _none, tables
}
