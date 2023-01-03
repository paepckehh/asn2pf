// package asn2pf ...
package asn2pf

import (
	"bufio"
	"compress/gzip"
	"errors"
	"io"
	"os"

	"github.com/klauspost/compress/zstd"
)

// const
const (
	_app      = "[asn2pf]   "
	_err      = _app + "[error] "
	_inf      = _app + "[info] "
	_empty    = ""
	_linefeed = "\n"
)

// out ...
func out(msg string) { os.Stdout.Write([]byte(msg + _linefeed)) }

// info ...
func info(msg string) { out(_inf + msg) }

// pad ...
func pad(in string, l int) string {
	for len(in) < l {
		in = in + " "
	}
	return in
}

// getFileScanner ...
func getFileScanner(name string) (s *bufio.Scanner, err error) {
	r, err := getReader(name)
	if err != nil {
		return s, errors.New("[compress] [scanner] unable to read file [" + name + "] [" + err.Error() + "]")
	}
	return bufio.NewScanner(r), nil
}

// getReader ...
func getReader(name string) (io.Reader, error) {
	var r io.Reader
	l := len(name)
	if l < 3 {
		return r, errors.New("[compress] [scanner] unable to read file [" + name + "] [unknown extension]")
	}
	f, err := os.Open(name)
	if err != nil {
		return r, errors.New("[compress] [scanner] unable to read file [" + name + "] [" + err.Error() + "]")
	}
	switch name[len(name)-3:] {
	case "zst":
		r, err = zstd.NewReader(f)
	case ".gz":
		r, err = gzip.NewReader(f)
	case "tsv", "txt", "csv":
		r = f
	default:
		return r, errors.New("[compress] [internal] unsupported format")
	}
	if err != nil {
		return r, errors.New("[compress] [scanner] unable to read file [" + name + "] [" + err.Error() + "]")
	}
	return r, nil
}
