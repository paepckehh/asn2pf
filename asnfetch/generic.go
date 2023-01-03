// package asnfetch ...
package asnfetch

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"syscall"

	"github.com/klauspost/compress/zstd"
)

// const
const (
	_app      = "[asnfetch] "
	_err      = _app + "[error] "
	_inf      = _app + "[info] "
	_empty    = ""
	_linefeed = "\n"
)

// out ...
func out(msg string) { os.Stdout.Write([]byte(msg + _linefeed)) }

// info ...
func info(msg string) { out(_inf + msg) }

// errOut ...
func errOut(msg string) { out(_err + msg) }

// isReadable ...
func isReadable(filename string) bool {
	f, err := os.Open(filename)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// isEnv ...
func isEnv(in string) bool {
	if _, ok := syscall.Getenv(in); ok {
		return true
	}
	return false
}

// compress
func compress(algo string, level int, in []byte) []byte {
	switch algo {
	case "ZSTD", "GZIP":
		return compressGO(algo, level, in)
	}
	errOut("internal error: unsupported compress algo [" + algo + "]")
	return nil
}

// decompress
func decompress(algo string, in []byte) []byte {
	switch algo {
	case "ZSTD", "GZIP":
		return decompressGO(algo, in)
	}
	errOut("internal error: unsupported decompress algo [" + algo + "]")
	return nil
}

// decompressGO
func decompressGO(algo string, data []byte) []byte {
	if algo == "" {
		return data
	}
	var err error
	var r io.Reader
	br := bytes.NewReader(data)
	switch algo {
	case "ZSTD":
		r, err = zstd.NewReader(br)
	case "GZIP":
		r, err = gzip.NewReader(br)
	default:
		errOut("unsupported de-compress algo [" + algo + "]")
		return nil
	}
	if err != nil {
		errOut("unable to create new de-compress reader [" + algo + "]")
		return nil
	}
	out, err := io.ReadAll(r)
	if err != nil {
		errOut("[decompress] [" + algo + "] [" + err.Error() + "]")
		return nil
	}
	return out
}

func compressGO(algo string, level int, data []byte) []byte {
	if algo == "" || level == 0 {
		return data
	}
	var buf bytes.Buffer
	switch algo {
	case "ZSTD":
		if level > 19 {
			level = 19
		}
		w, err := zstd.NewWriter(nil,
			zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(level)),
			zstd.WithEncoderCRC(false),
			zstd.WithZeroFrames(false),
			zstd.WithSingleSegment(true),
			zstd.WithLowerEncoderMem(false),
			zstd.WithAllLitEntropyCompression(true),
			zstd.WithNoEntropyCompression(false))
		if err != nil {
			errOut("unable to create new zstd writer [" + err.Error() + "]")
			return nil
		}
		out := w.EncodeAll(data, nil)
		w.Close()
		return out
	case "GZIP":
		if level > 9 {
			level = 9
		}
		w, err := gzip.NewWriterLevel(&buf, level)
		if err != nil {
			errOut("unable to create new gzip writer [" + err.Error() + "]")
			return nil
		}
		if _, err = w.Write(data); err != nil {
			errOut("unable to write via gzip writer [" + err.Error() + "]")
			return nil
		}
		w.Close()
	default:
		errOut("unsupported compression algo [requested:" + algo + "]")
		return nil
	}
	r := io.Reader(&buf)
	out, err := io.ReadAll(r)
	if err != nil {
		errOut("[compress] [algo:" + algo + "] [" + err.Error() + "]")
		return nil
	}
	return out
}
