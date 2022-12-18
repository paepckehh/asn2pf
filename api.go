// package asn2pf ...
package asn2pf

import (
	"os"
	"strings"
	"time"

	"paepcke.de/asn2pf/asnfetch"
)

// GenerateTables ...
func GenerateTables(file, store string, fetch, noip4, noip6 bool, cmd_terms []string, skiplist string) {
	// setup
	t0 := time.Now()

	// setup header
	now := string(t0.Format(time.RFC3339))
	tables := []byte(_H1 + _H2 + _H3 + "[ " + now + " ]" + _LF + _H1 + _H4 + "\"" + file + "\"" + _LF + _H5 + _LF)

	// verify, fetch, report sources
	srcdb := asnfetch.GetSRCDB(store, fetch, noip4, noip6)

	// expander | sanitizer for commandline options
	querys, table_opts, rule, workmode, tables := parseOptions(cmd_terms, tables, srcdb)

	// report
	if workmode == _none {
		info(pad("file", 30) + file)
	}
	if table_opts != "" {
		info(pad("table options", 30) + table_opts)
	}
	if rule != "" {
		info(pad("firewall rules", 30) + rule)
	}

	// quick header only exit
	if len(querys) < 1 && workmode == _none {
		info("no [valid] query(s) defined -> no tables")
		time.Sleep(10 * time.Millisecond) // todo: ctx need for logsec daemon shutdown
		return
	}

	// parse sourcefiles
	tables = append(tables, parser_tsv5(srcdb, table_opts, querys)...)

	if skiplist != "" {
		t := string(tables)
		info(pad("Skiplist", 30))
		for _, skip := range strings.Split(skiplist, "#") {
			t = strings.ReplaceAll(t, " "+skip+" ", " ")
			info("[" + skip + "] ")
		}
		tables = []byte(t)
		info(_empty)
	}

	// write
	if err := os.WriteFile(file, tables, 0o660); err != nil {
		info("unable to write table [" + err.Error() + "]")
	}

	// report
	info(pad("time needed", 30) + time.Since(t0).String())
	time.Sleep(10 * time.Millisecond) // todo: ctx need for logsec daemon shutdown
}
