package asn2pf

import (
	"sort"
	"strconv"
	"strings"
	"sync"
)

// cache table asn -> network(s)
type asn_chan_entry struct {
	asn    uint64 // map key
	prefix []byte // map value
}

// cache table owner -> asn(s)
type owner_chan_entry struct {
	owner string // map key
	asn   uint64 // map value
}

func parser_tsv5_cache(src Source, worker int) {
	// channel setup
	feed_chan := make(chan string, 1000)
	asn_chan := make(chan asn_chan_entry, 1000)
	owner_chan := make(chan owner_chan_entry, 1000)

	// parser worker(s)
	go func() {
		bg := sync.WaitGroup{}
		bg.Add(worker)
		for i := 0; i < worker; i++ {
			go func() {
				for line := range feed_chan {
					s := strings.Split(line, "\t")
					if len(s) != 5 {
						OutErr("SKIP [" + line + "] [#]")
						continue
					}
					asn, err := strconv.ParseUint(s[2], 10, 0)
					if err != nil {
						OutErr("SKIP [" + line + "] [ASN]")
						continue
					}
					prefix := range2net_tailscale(s[0], s[1])
					if prefix == nil {
						OutErr("SKIP: [" + line + "] [RANGE]")
						continue
					}
					asn_chan <- asn_chan_entry{
						asn:    asn,
						prefix: prefix,
						// prefix: []byte(s[0] + "-" + s[1]+"#"),
					}
					owner_chan <- owner_chan_entry{
						owner: strings.ToUpper(s[3]) + "#" + strings.ToLower(s[4]),
						asn:   asn,
					}
				}
				bg.Done()
			}()
		}
		bg.Wait()
		close(asn_chan)
		close(owner_chan)
	}()

	// build collector group
	cg := sync.WaitGroup{} // [c]ollector wait [g]roup
	cg.Add(2)              // two channel to collect
	_LF := []byte("\n")
	_SEP := []byte("\t")
	go func() {
		// build asn -> network(s) map
		go func() {
			asn_map := make(map[uint64][]byte)
			for asn := range asn_chan {
				if _, ok := asn_map[asn.asn]; ok {
					// case: asn key exist => add net
					asn_map[asn.asn] = append(asn_map[asn.asn], asn.prefix...)
					continue
				}
				// case: new asn
				asn_map[asn.asn] = asn.prefix
			}

			Out("collect asn done")

			// create sort index [faster processing & better compression results]
			sort_index := make([]uint64, 0, len(asn_map))
			for x := range asn_map {
				sort_index = append(sort_index, x)
			}
			sort.Slice(sort_index, func(i, j int) bool { return sort_index[i] < sort_index[j] })

			Out("sort asn done")

			// write map
			out := []byte{}
			for _, asn := range sort_index {
				out = append(out, []byte(strconv.FormatUint(asn, 10)+"\t")...)
				out = append(out, asn_map[asn]...)
				out = append(out, _LF...)
			}
			WriteFile("./cache_asn", []byte(out), 0o660)
			Out("write asn done")
			cg.Done()
		}()

		// build owner -> asn(s) map
		go func() {
			owner_map := make(map[string][]uint64)
			for owner := range owner_chan {
				if asn, ok := owner_map[owner.owner]; ok {
					for _, a := range asn {
						if a == owner.asn {
							// case: owner key exist, asn is already member
							continue
						}
					}
					// case: owner key exist, but new asn => add asn
					asn = append(asn, owner.asn)
					owner_map[owner.owner] = asn
					continue
				}
				// case: new owner
				owner_map[owner.owner] = []uint64{owner.asn}
			}

			Out("collect owner done")

			// create sort index
			sort_index := make([]string, 0, len(owner_map))
			for x := range owner_map {
				sort_index = append(sort_index, x)
			}
			sort.Strings(sort_index)

			Out("sort owner done")

			// write map
			out := []byte{}
			for _, owner := range sort_index {
				asn_list := []byte{}
				for _, a := range owner_map[owner] {
					asn_list = append(asn_list, []byte(strconv.FormatUint(a, 10)+" ")...)
				}
				l := len(asn_list)
				if l > 1 {
					asn_list = asn_list[:l-1]
				}
				out = append(out, []byte(owner)...)
				out = append(out, _SEP...)
				out = append(out, asn_list...)
				out = append(out, _LF...)
			}
			WriteFile("./cache_owner", []byte(out), 0o660)
			Out("write owner done")
			cg.Done()
		}()
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

	cg.Wait()
	return
}
