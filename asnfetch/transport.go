// package asnfetch ...
package asnfetch

// import
import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	//"errors"
	"net/http"
	"net/url"
)

// getTlsConf ...
func getTlsConf(keyPin string) *tls.Config {
	tlsConfig := &tls.Config{
		InsecureSkipVerify:     false,
		SessionTicketsDisabled: true,
		Renegotiation:          0,
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CipherSuites:           []uint16{tls.TLS_CHACHA20_POLY1305_SHA256},
		//CurvePreferences:       []tls.CurveID{tls.X25519},
	}
	//if keyPin != _empty {
	//	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
	//		if !pinVerifyState(keyPin, &state) {
	//			return errors.New("keypin verification failed")
	//		}
	//		return nil
	//	}
	//}
	return tlsConfig
}

// pinVerifyState ...
func pinVerifyState(keyPin string, state *tls.ConnectionState) bool {
	if len(state.PeerCertificates) > 0 {
		if keyPin == keyPinBase64(state.PeerCertificates[0]) {
			return true
		}
	}
	return false
}

// keyPinBase64 ...
func keyPinBase64(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(h[:])
}

// getTransport ...
func getTransport(tlsconf *tls.Config) *http.Transport {
	return &http.Transport{
		Proxy:              http.ProxyFromEnvironment,
		TLSClientConfig:    tlsconf,
		DisableCompression: true, // pre-compressed file downloads
		ForceAttemptHTTP2:  false,
	}
}

// getClient ...
func getClient(transport *http.Transport) *http.Client {
	return &http.Client{
		CheckRedirect: nil,
		Jar:           nil,
		Transport:     transport,
	}
}

// getRequest ...
func getRequest(targetURL, userAgent string) (*http.Request, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		errOut("[DB] [" + targetURL + "] -> invalid src url syntax [" + err.Error() + "]")
		return &http.Request{}, err
	}
	return &http.Request{
		URL:        u,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"User-Agent": []string{userAgent},
		},
	}, nil
}
