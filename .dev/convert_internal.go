package asn2pf

// internal opimized converter implementation
// faster, smaller,  dependency free & and more eco friendly - but currently ip4 only!

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

func range2net_internal(s, e string) (cidrs []byte) {
	start, end := ip2int(s), ip2int(e)
	cidr2mask := get_cidr_ipv4_masks()
	for end >= start {
		maxSize := 32
		for maxSize > 0 {
			maskedBase := start & cidr2mask[maxSize-1]
			if maskedBase != start {
				break
			}
			maxSize--
		}
		x := math.Log(float64(end-start+1)) / math.Log(2)
		maxDiff := 32 - int(math.Floor(x))
		if maxSize < maxDiff {
			maxSize = maxDiff
		}
		cidrs = append(cidrs, []byte(int2ip(start)+"/"+strconv.Itoa(maxSize)+" ")...)
		start += uint32(math.Exp2(float64(32 - maxSize)))
	}
	return
}

func ip2int(ip string) uint32 {
	octets := [4]uint64{}
	for i, v := range strings.SplitN(ip, ".", 4) {
		octets[i], _ = strconv.ParseUint(v, 10, 32)
	}
	return uint32((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3])
}

func int2ip(ip uint32) (iP string) {
	return fmt.Sprintf("%d.%d.%d.%d", ip>>24, (ip&0x00FFFFFF)>>16, (ip&0x0000FFFF)>>8, ip&0x000000FF)
}

func get_cidr_ipv4_masks() []uint32 {
	return []uint32{
		0x00000000, 0x80000000, 0xC0000000,
		0xE0000000, 0xF0000000, 0xF8000000,
		0xFC000000, 0xFE000000, 0xFF000000,
		0xFF800000, 0xFFC00000, 0xFFE00000,
		0xFFF00000, 0xFFF80000, 0xFFFC0000,
		0xFFFE0000, 0xFFFF0000, 0xFFFF8000,
		0xFFFFC000, 0xFFFFE000, 0xFFFFF000,
		0xFFFFF800, 0xFFFFFC00, 0xFFFFFE00,
		0xFFFFFF00, 0xFFFFFF80, 0xFFFFFFC0,
		0xFFFFFFE0, 0xFFFFFFF0, 0xFFFFFFF8,
		0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFFF,
	}
}
