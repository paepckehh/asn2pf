package asn2pf

import (
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"math/bits"
	"os"
	"runtime"
	"strconv"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

//
// EXTERNAL INTERFACE
//

func decompress(algo string, in []byte) []byte {
	switch algo {
	case "xz":
		switch {
		case IsExec(_exec_xz):
			return decompress_cmd(_exec_xz, in)
		}
		return decompress_go(algo, in)
	case "gzip":
		switch {
		case IsExec(_exec_gzip):
			return decompress_cmd(_exec_gzip, in)
		}
		return decompress_go(algo, in)
	case "zstd":
		switch {
		case IsExec(_exec_zstd):
			return decompress_cmd(_exec_zstd, in)
		}
		return decompress_go(algo, in)
	}
	panic("internal error: unsupported decompress algo [" + algo + "]")
}

func compress(algo string, level int, in []byte) []byte {
	switch algo {
	case "xz":
		switch {
		case IsExec(_exec_xz):
			return compress_cmd(_exec_xz, level, in)
		}
		return compress_go(algo, level, in)
	case "gzip":
		switch {
		case IsExec(_exec_gzip):
			return compress_cmd(_exec_gzip, level, in)
		}
		return compress_go(algo, level, in)
	case "zstd":
		switch {
		case IsExec(_exec_zstd):
			return compress_cmd(_exec_zstd, level, in)
		}
		return compress_go(algo, level, in)
	}
	panic("internal error: unsupported compression algo [" + algo + "]")
}

//
// INTERNAL BACKEND: NATIVE GO
//

func decompress_go(algo string, in []byte) (out []byte) {
	br := bytes.NewReader(in)
	var err error
	var r io.Reader
	switch algo {
	case "xz":
		r, err = xz.NewReader(br)
	case "gzip":
		r, err = gzip.NewReader(br)
	case "zstd":
		r, err = zstd.NewReader(br)
	default:
		panic("internal error: unsupported native go decompress algo [" + algo + "]")
	}
	if err != nil {
		panic("internal error: unable to create new decompress reader [" + algo + "]")
	}
	out, err = io.ReadAll(r)
	if err != nil {
		OutErr("decompress block [" + algo + "]")
		return
	}
	return
}

func compress_go(algo string, level int, in []byte) (out []byte) {
	threads := runtime.NumCPU()
	switch algo {
	case "zstd":
		switch bits.UintSize {
		case 32:
			OutInf("32bit os mem addr range alloc workaround activated [slow single threaded mode]")
			runtime.GC()
			threads = 1
		}
		w, err := zstd.NewWriter(nil,
			zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(level)),
			zstd.WithEncoderCRC(false),
			zstd.WithZeroFrames(false),
			zstd.WithLowerEncoderMem(false),
			zstd.WithAllLitEntropyCompression(true),
			zstd.WithNoEntropyCompression(false),
			zstd.WithWindowSize(zstd.MaxWindowSize),
			zstd.WithEncoderConcurrency(threads))
		if err != nil {
			panic("internal error: unable to create new ecompress writer [" + algo + "]")
		}
		out = w.EncodeAll(in, nil)
		w.Close()
	default:
		panic("internal error: unsupported native go compress algo [" + algo + "]")
	}
	return
}

//
// INTERNAL BACKENDS: CMD PIPE WRAPPER
//

const (
	_exec_xz   = "DISABLE/usr/bin/xz"
	_exec_gzip = "DISABLE/usr/bin/gzip"
	_exec_zstd = "DISABLE/usr/bin/zstd"
)

func decompress_cmd(exec string, in []byte) (out []byte) {
	cmdopt := " --decompress --stdin --stdout --quiet"
	switch exec {
	case _exec_xz:
	case _exec_gzip:
	case _exec_zstd:
	default:
		panic("internal error: unsupported cmd decompress [" + exec + "]")
	}
	/*
		cmd := exec.Command(exec,cmdopt)
		cmd.Stdout =
		cmd.Stderr = os.Stdout
		cmd.Stdin =
		cmd.Start()
		cmd.Wait()
	*/
	_ = in
	_ = cmdopt
	return
}

func compress_cmd(exec string, level int, in []byte) (out []byte) {
	cmdopt := " --compress --stdin --stdout --quiet "
	threads := runtime.NumCPU()
	switch exec {
	case _exec_xz:
	case _exec_gzip:
	case _exec_zstd:
		switch bits.UintSize {
		case 32:
			if level > 6 {
				threads = 1
				if level > 19 {
					level = 19
				}
			}
		case 64:
			if level > 19 {
				cmdopt += " --ultra --long"
			}
		default:
			panic("unsupported os plattform, no [32bit|64bit]")
		}
		cmdopt += "-" + strconv.Itoa(level) + " --threads=" + strconv.Itoa(threads)
	default:
		panic("internal error: unsupported cmd compress [" + exec + "]")
	}
	/*
		cmd := exec.Command(exec, cmdopt)
		cmd.Stdout =
		cmd.Stderr = os.Stdout
		cmd.Stdin =
		cmd.Start()
		cmd.Wait()
	*/
	_ = in
	_ = cmdopt
	return
}

//
// INTERNAL BACKENDS: CGO BINDINGS
//

//
// Little Helper
//

func IsExec(filename string) bool {
	inf, err := os.Lstat(filename)
	if err != nil {
		return false
	}
	switch mode := inf.Mode(); {
	case mode.IsRegular():
		return true
	case mode&fs.ModeSymlink != 0:
		return true
	}
	return false
}
