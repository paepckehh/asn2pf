package asn2pf

import (
	"runtime"
	"strconv"
	"strings"
	"sync"

	"paepcke.de/asn2pf/asnfetch"
	"paepcke.de/asn2pf/range2cidr"
)

const (
	_tab      = "\t"
	_lineFeed = '\n'
	_lineSize = 256
	_ip4      = "_ip4"
	_ip6      = "_ip6"
)

// query term
type query struct {
	mode int    // search mode
	term string // search term
	name string // search table name
}

// feed
type feed struct {
	line string
	ipv4 bool
	ipv6 bool
}

// table entry
type table_chan_entry struct {
	table string // taret table name
	cidrs []byte // the resulting cidr nets for range
}

func parser_tsv5(src []asnfetch.Source, table_opts string, querys []query) []byte {
	// generic
	worker := runtime.NumCPU()

	// channel setup
	feed_chan := make(chan feed, 1000*worker)
	collect_chan := make(chan table_chan_entry, 1000*worker)

	// worker
	go func() {
		bg := sync.WaitGroup{}
		bg.Add(worker)
		for i := 0; i < worker; i++ {
			go func() {
				for l := range feed_chan {
					for _, query := range querys {
						s := strings.Split(l.line, _tab)
						if len(s) != 5 {
							info("SKIP [" + l.line + "] [#]")
							continue
						}
						table := ""
						switch query.mode {
						case _asn:
							if s[2] != query.term {
								continue
							}
							table = "asn_" + query.term
						case _country:
							if s[3] != query.term {
								continue
							}
							table = "country_" + query.term
						case _owner:
							if !strings.Contains(strings.ToLower(s[4]), query.term) {
								continue
							}
							table = "owner_" + query.term
						case _ownerPrefix:
							if !strings.HasPrefix(strings.ToLower(s[4]), query.term) {
								continue
							}
							table = "owner_" + query.term
						default:
							panic("undefined search mode")
						}
						if query.name != "" {
							table = query.name
						}
						switch {
						case l.ipv4:
							collect_chan <- table_chan_entry{
								table: table + _ip4,
								cidrs: range2cidr.Slice(s[0], s[1]),
							}
						case l.ipv6:
							collect_chan <- table_chan_entry{
								table: table + _ip6,
								cidrs: range2cidr.Slice(s[0], s[1]),
							}
						}
					}
				}
				bg.Done()
			}()
		}
		bg.Wait()
		close(collect_chan)
	}()

	// feeder
	go func() {
		for _, s := range src {
			scanner, err := getFileScanner(s.File)
			if err != nil {
				info(err.Error())
				continue
			}
			for scanner.Scan() {
				feed_chan <- feed{scanner.Text(), s.IPv4, s.IPv6}
			}
		}
		close(feed_chan)
	}()

	// collect
	lq := len(querys)
	table_cap := lq * 256
	table_map := make(map[string][]byte, lq)
	for asn := range collect_chan {
		table_cap += len(asn.cidrs)
		table_map[asn.table] = append(table_map[asn.table], asn.cidrs...)
	}

	// pre-alloc, assemble tables
	table := make([]byte, 0, table_cap)
	for tablename, cidrs := range table_map {
		tablename = strings.ToLower(tablename)
		table = append(table, []byte("\ntable <"+tablename+"> "+table_opts+" { ")...)
		table = append(table, cidrs...)
		table = append(table, []byte("}\n\n")...)
		// report
		c := strings.Split(string(cidrs), " ")
		info(pad(" + table "+tablename, 40) + pad(strconv.Itoa(len(c)), 7) + " item(s)")
	}
	return table
}
