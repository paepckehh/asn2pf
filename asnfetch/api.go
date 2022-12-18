// package ansfetch validates, converts and fetchs missing asn db source files
package asnfetch

// import
import (
	"os"
	"runtime"
)

// Node ...
type Node struct {
	Domain    string   // domain name
	TLSKeyPin []string // TLS SHA2 KeyPins
}

// Source ...
type Source struct {
	File      string   // asn db local file [cache] location
	Signature string   // asn db local file [cache] signature
	SizeMB    float32  // asn db local file size rough estimate in MegaByte(s)
	SignerKey string   // asn db signers public key
	Domain    string   // source domain name
	TrustCA   string   // pem file for root ca[s] trust anchor
	TLSKeyPin []string // tls cert sha2 keypin
	Url       string   // source url file db
	Urls      string   // source url file db signature
	Proxy     string   // db fetch
	ProxyCert string   // db fetch
	UserAgent string   // db fetch
	IPv4      bool     // source provides IPv4 entries
	IPv6      bool     // source provides IPv6 entries
	Parser    string   // asn db parser
}

// GetSRCDB ...
func GetSRCDB(store string, fetch, noip4, noip6 bool) (srcdb []Source) {
	if store == "" {
		store = "/tmp"
		errOut("[asnfetch] db src store|cache not defined, fallback to unsecure /tmp")
	}
	db := getSourceDB(store, noip4, noip6)
	for _, src := range db {
		l := len(src.File)
		zFile := src.File[:l-3] + ".zst"

		// try fetch db.src.Url if db.src.File is missing
		if !isReadable(src.File) && !isReadable(zFile) {
			if fetch {
				if !fetchSRC(src) {
					errOut("[asnfetch] unable to [read|download] source db [" + src.File + "]")
					continue
				}
			} else {
				continue
			}
		}

		// try to upgrade from gz to zstd if available
		if isReadable(zFile) {
			src.File = zFile
		} else {
			// try if we [need|can] convert gz to zstd
			if src.File[l-3:] == ".gz" && isReadable(src.File) {
				info("convert [" + src.File + "] to [" + zFile + "] for faster processing")
				if data, err := os.ReadFile(src.File); err == nil {
					data := compress("ZSTD", 22, decompress("GZIP", data))
					if err := os.WriteFile(zFile, data, 0o660); err != nil {
						errOut("unable to write file [" + err.Error() + "]")
					}
					src.File = zFile
					runtime.GC()
				}
			}
		}

		// add db.src
		srcdb = append(srcdb, src)
		info("[asnfetch] source_db [" + src.File + "]")

	}
	return srcdb
}
