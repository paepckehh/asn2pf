package asn2pf

import (
	"fmt"
	"strings"
	"sync"

	"github.com/mikioh/ipaddr"
	"inet.af/netaddr"
)

// table entry
type table_chan_entry struct {
	table string             // taret table name
	cidrs []netaddr.IPPrefix // the resulting cidr nets for range
	//	cidrs []byte // the resulting cidr nets for range
}

func parser_tsv5(src Source, table_opts string, querys []query, worker int) []byte {
	// channel setup
	feed_chan := make(chan string, 1000)
	collect_chan := make(chan table_chan_entry, 1000)

	// worker
	go func() {
		bg := sync.WaitGroup{}
		bg.Add(worker)
		for i := 0; i < worker; i++ {
			go func() {
				for line := range feed_chan {
					for _, query := range querys {
						s := strings.Split(line, "\t")
						if len(s) != 5 {
							OutErr("SKIP [" + line + "] [#]")
							continue
						}
						table := ""
						switch query.mode {
						case _asn:
							if s[2] != query.term {
								continue
							}
							table = "asn_" + query.term
						case _owner:
							if !strings.Contains(strings.ToLower(s[4]), query.term) {
								continue
							}
							table = "owner_" + query.term
						case _country:
							if s[3] != query.term {
								continue
							}
							table = "country_" + query.term
						default:
							panic("undefined search mode")
						}
						netrange, err := netaddr.ParseIPRange(s[0] + "-" + s[1])
						if err != nil {
							OutErr("SKIP - unable to parse range [" + s[0] + "-" + s[1] + "]")
							return
						}
						collect_chan <- table_chan_entry{
							table: table,
							cidrs: netrange.Prefixes(),
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
		if scanner, ok := getFileScanner(src.File); ok {
			for scanner.Scan() {
				feed_chan <- scanner.Text()
			}
		}
		close(feed_chan)
	}()

	// collect
	lq := len(querys)
	// table_cap := lq * 256
	table_map := make(map[string][]ipaddr.Prefix, lq)
	for asn := range collect_chan {
		for _, cidr := range asn.cidrs {
			p, err := ipaddr.Parse(cidr.String())
			if err != nil {
				OutErr("SKIP - unable to parse range " + cidr.String())
				continue
			}
			px := p.List()
			for _, c := range px {
				table_map[asn.table] = append(table_map[asn.table], c)
			}
		}
	}

	// consolidate [aggregate]
	for table_name, prefixes := range table_map {
		before := len(table_map[table_name])
		table_map[table_name] = ipaddr.Aggregate(prefixes)
		after := len(table_map[table_name])
		fmt.Printf("before: v%  after: v%", before, after)
	}
	panic("EXIT")
	/*
		// table_cap += len(asn.cidrs)
		// pre-alloc, assemble tables
		table := make([]byte, 0, table_cap)
		for tablename, cidrs := range table_map {
			tablename = strings.ToLower(tablename + "_" + src.TableID)
			table = append(table, []byte("\ntable <"+tablename+"> "+table_opts+" { ")...)
			table = append(table, cidrs...)
			table = append(table, []byte("}\n\n")...)
			// report
			c := strings.Split(string(cidrs), " ")
			Out(Pad(" + table "+tablename, 40) + Pad(strconv.Itoa(len(c)), 7) + " item(s)")
		}
	*/
	return nil
}
