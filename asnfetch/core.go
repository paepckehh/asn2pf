// package ansfetch validates, converts and fetchs missing asn db source files
package asnfetch

// import
import (
	"io"
	"os"
	"time"
)

// const
const (

	//
	_DEFAULT_USERAGENT = "curl" // user agent used for fetch
	_DEFAULT_TRUSTCA   = ""     // optional ca [root] trust anchor[s] pem file
	_DEFAULT_PROXY     = ""     // optional outbound proxy
	_DEFAULT_PROXYCERT = ""     // optiobal outbound proxy trust ca pem file

	//
	_ENV_NO_IPV4 = "NO_IPV4"
	_ENV_NO_IPV6 = "NO_IPV6"
)

// getNodes ...
func getNodes() (nodes []Node) {
	node := Node{
		Domain:    "iptoasn.com",
		TLSKeyPin: []string{"Ag4F6GDvw2Zvg0xHdyj1WE2NNzDO9HDR8TUtxWO9eQ8=", "FEzVOUp4dF3gI0ZVPRJhFbSJVXR+uQmMH65xhs1glH4="},
	}
	nodes = append(nodes, node)
	return nodes
}

// getSourceDB ...
func getSourceDB(store string, noip4, noip6 bool) (srcdb []Source) {
	if store[len(store)-1:] != "/" {
		store += "/"
	}
	for _, n := range getNodes() {
		src := Source{}
		if !isEnv(_ENV_NO_IPV4) && !noip4 {
			src = Source{
				File:      store + "ip2asn-v4.tsv.gz",
				Signature: store + "ip2asn-v4.tsv.gz.sig",
				SizeMB:    6.1, // rough estimate
				SignerKey: "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
				Domain:    n.Domain,
				Url:       "https://" + n.Domain + "/data/ip2asn-v4.tsv.gz",
				Urls:      "https://" + n.Domain + "/data/ip2asn-v4.tsv.gz.sig",
				TrustCA:   _DEFAULT_TRUSTCA,
				TLSKeyPin: n.TLSKeyPin,
				UserAgent: _DEFAULT_USERAGENT,
				Proxy:     _DEFAULT_PROXY,
				ProxyCert: _DEFAULT_PROXYCERT,
				IPv4:      true,
				IPv6:      false,
				Parser:    "tsv5",
			}
			srcdb = append(srcdb, src)
		}
		if !isEnv(_ENV_NO_IPV6) && !noip6 {
			src = Source{
				File:      store + "ip2asn-v6.tsv.gz",
				Signature: store + "ip2asn-v6.tsv.gz.sig",
				SizeMB:    1.3, // rough estimate
				SignerKey: "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
				Domain:    n.Domain,
				Url:       "https://" + n.Domain + "/data/ip2asn-v6.tsv.gz",
				Urls:      "https://" + n.Domain + "/data/ip2asn-v6.tsv.gz.sig",
				TrustCA:   _DEFAULT_TRUSTCA,
				TLSKeyPin: n.TLSKeyPin,
				UserAgent: _DEFAULT_USERAGENT,
				Proxy:     _DEFAULT_PROXY,
				ProxyCert: _DEFAULT_PROXYCERT,
				IPv4:      false,
				IPv6:      true,
				Parser:    "tsv5",
			}
			srcdb = append(srcdb, src)
		}
	}
	return srcdb
}

// fetchSRC
func fetchSRC(src Source) bool {
	var err error

	// setup request
	request, err := getRequest(src.Url, src.UserAgent)
	if err != nil {
		errOut("[DB] unable to fetch source db: " + err.Error())
		return false
	}

	// setup transport layer
	tlsconf := getTlsConf(_empty)
	transport := getTransport(tlsconf)
	client := getClient(transport)

	// report
	info("[DB] local db file [" + src.File + "] missing!")
	info("[DB] fetch [" + src.Url + "]")

	// fetch head
	client.Timeout = time.Duration(10 * time.Second)
	request.Method = "HEAD"
	head, err := client.Do(request)
	if err != nil || head.Header.Get("Content-Type") != "application/binary" || head.StatusCode > 299 {
		errOut("[DB] unable to fetch source db [" + src.Url + "] [FETCH HEAD FAIL]")
		errOut(err.Error())
		return false
	}

	// setup limits and targetslice
	size := src.SizeMB * 1024 * 1024
	maxsize := int(size * 1.8)
	minsize := int(size * 0.6)
	data := make([]byte, 0, maxsize)

	// fetch, write file
	client.Timeout = time.Duration(30 * time.Second)
	request.Method = "GET"
	body, err := client.Do(request)
	data, err = io.ReadAll(body.Body)
	if err != nil || body.StatusCode > 299 {
		errOut("[DB] unable to fetch db [" + src.Url + "] [FETCH BODY FAIL]")
		errOut(err.Error())
		return false
	}
	body.Body.Close()
	l := len(data)
	if l > maxsize || l < minsize {
		errOut("[DB] unable to fetch db [" + src.Url + "] [EXPECTED DOWNLOAD SIZE DO NOT MATCH]")
		errOut(err.Error())
		return false
	}
	if err := os.WriteFile(src.File, data, 0o660); err != nil {
		errOut("unable to write file [" + err.Error() + "]")
	}
	return true
}
