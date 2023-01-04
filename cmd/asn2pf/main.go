// package main ...
package main

// import ...
import (
	"os"
	"syscall"

	"paepcke.de/asn2pf"
)

// const shortcuts
const (
	// DEFAULTS  [convinient build time defaults]
	_APPNAME         = "ASN2PF"
	_DEFAULT_SRC     = "."
	_DEFAULT_OUTFILE = "./pf.asn-tables"
	_DEFAULT_SKIP    = ""

	// ENV VAR NAMES
	_ENV_SRC     = _APPNAME + "_SRC"
	_ENV_OUTFILE = _APPNAME + "_OUTFILE"
	_ENV_SKIP    = _APPNAME + "_SKIP"
)

// main ..
func main() {
	// syntax exit
	if len(os.Args) < 2 {
		syntax()
		os.Exit(1)
	}

	// ask env about target filename
	outfile := _DEFAULT_OUTFILE
	if env, ok := syscall.Getenv(_ENV_OUTFILE); ok {
		outfile = env
	}

	// ask env about skiplist
	skiplist := _DEFAULT_SKIP
	if env, ok := syscall.Getenv(_ENV_SKIP); ok {
		skiplist = env
	}

	// ask env about db source path prefix
	prefix := _DEFAULT_SRC + "/"
	if env, ok := syscall.Getenv(_ENV_SRC); ok {
		prefix = env + "/"
	}

	// get commandline options
	var terms []string
	for num, arg := range os.Args {
		if num > 0 {
			terms = append(terms, arg)
		}
	}

	// genetate table set, write
	asn2pf.GenerateTables(outfile, prefix, true, false, false, terms, skiplist)
}

// syntax ...
func syntax() {
	out("syntax : asn2pf [table options] [search terms]")
	out("example: asn2pf block drop log counters asn:0 facebook amazon netflix dod country:RU asn:3356 country:CN")
	out("")
	out("env vars")
	out("NO_[IPV4|IPV6]")
	out("ASN2PF_OUTFILE [output filename]")
	out("ASN2PF_SKIP [do not process this prefixes]")
	out("HTTPS_PROXY, SSL_CERT_[FILE|DIR]")
}

//
// LITTLE GENERIC HELPER SECTION
//

// out ...
func out(msg string) {
	os.Stdout.Write([]byte(msg + "\n"))
}
