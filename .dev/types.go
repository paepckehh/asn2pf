package asn2pf

import "inet.af/netaddr"

// Distribution Network
type DN struct {
	Nodes []Node // array of individual member nodes
}

// Individual DN Node
type Node struct {
	Domain    string   // domain name
	TLSKeyPin []string // TLS SHA2 KeyPins
}

// database of Sources
type DB struct {
	Sources []Source
}

// source definition
type Source struct {
	File      string   // asn db local file [cache] location
	Signature string   // asn db local file [cache] signature
	SizeMB    float32  // asn db local file size rough estimate in MegaByte(s)
	SignerKey string   // asn db signers public key
	Parser    string   // asn db parser
	TableID   string   // table identifier [eg ipv4|ipv6|mixed|*_source]
	Domain    string   // source domain name
	TLSKeyPin []string // tls cert sha2 keypin
	Url       string   // source url file db
	Urls      string   // source url file db signature
	Proxy     string   //
	UserAgent string   //
}

// query term
type query struct {
	idx  int    // search term idx
	mode string // search mode
	term string // search term
}

// table entry
type table_entry struct {
	table string             // taret table name
	cidrs []netaddr.IPPrefix // the resulting cidr nets for range
}
