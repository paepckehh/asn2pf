// [2022/01/20] [paepcke.de/internal/range2cidr]
// forked as [minimal|static|fast|boiled-down|optimized|single-purpose] import-only!
//
// [forked] from [go4.af/intern]
// Copyright 2020 Brad Fitzpatrick. All rights reserved.
// Use of this source code is governed by a BSD-style license.
//
// [forked] from [inet.af/netddr]
// Copyright 2020 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style license.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
//   - Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//   - Redistributions in binary form must reproduce the above
//     copyright notice, this list of conditions and the following disclaimer
//     in the documentation and/or other materials provided with the distribution.
//   - Neither the name of Tailscale Inc. nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
package range2cidr

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
	"runtime"
	"strings"
	"sync"
	"unsafe"
)

//
// EXTERNAL INTERFACE
//

const _space = ' '

// Slice [validate|sanitize] range to cidr slice
func Slice(s, e string) (prefix []byte) {
	netrange, _ := parseipRange(s + "-" + e)
	prefixes := netrange.prefixes()
	for _, p := range prefixes {
		net, _ := p.marshalText()
		prefix = append(prefix, net...)
		prefix = append(prefix, _space)
	}
	return prefix
}

// Array [validate|sanitize] range to cidr array
// func Array(s, e string) (prefix [][]byte) {
// 	netrange, _ := parseipRange(s + "-" + e)
// 	prefixes := netrange.prefixes()
// 	prefix = make([][]byte, len(prefixes))
// 	for i, p := range prefixes {
// 		net, _ := p.marshalText()
// 		prefix[i] = net
// 	}
// 	return prefix
// }

//
// INTERNAL BACKEND
//

// IP ...
type IP struct {
	addr uint128
	z    *value
}
type ipRange struct {
	from IP
	to   IP
}
type uint128 struct {
	hi uint64
	lo uint64
}
type prefixMaker func(a uint128, xbits uint8) ipPrefix

func (u *uint128) halves() [2]*uint64               { return [2]*uint64{&u.hi, &u.lo} }
func u64CommonPrefixLen(a, b uint64) uint8          { return uint8(bits.LeadingZeros64(a ^ b)) }
func (u uint128) not() uint128                      { return uint128{^u.hi, ^u.lo} }
func (u uint128) isZero() bool                      { return u.hi|u.lo == 0 }
func (u uint128) bitsSetFrom(bit uint8) uint128     { return u.or(mask6[bit].not()) }
func (u uint128) bitsClearedFrom(bit uint8) uint128 { return u.and(mask6[bit]) }
func (u uint128) or(m uint128) uint128              { return uint128{u.hi | m.hi, u.lo | m.lo} }
func (u uint128) and(m uint128) uint128             { return uint128{u.hi & m.hi, u.lo & m.lo} }
func (u uint128) xor(m uint128) uint128             { return uint128{u.hi ^ m.hi, u.lo ^ m.lo} }
func (u uint128) commonPrefixLen(v uint128) (n uint8) {
	if n = u64CommonPrefixLen(u.hi, v.hi); n == 64 {
		n += u64CommonPrefixLen(u.lo, v.lo)
	}
	return n
}

type value struct {
	_           [0]func()
	cmpVal      any
	resurrected bool
}
type key struct {
	s        string
	cmpVal   any
	isString bool
}

var (
	mu      sync.Mutex
	valMap  = map[key]uintptr{}
	valSafe = safeMap()
)

func safeMap() map[key]*value {
	return nil
}

func (k key) value() *value {
	if k.isString {
		return &value{cmpVal: k.s}
	}
	return &value{cmpVal: k.cmpVal}
}
func (v *value) Get() any { return v.cmpVal }
func comparePrefixes(a, b uint128) (common uint8, aZeroBSet bool) {
	common = a.commonPrefixLen(b)
	if common == 128 {
		return common, true
	}
	m := mask6[common]
	return common, (a.xor(a.and(m)).isZero() &&
		b.or(m) == uint128{^uint64(0), ^uint64(0)})
}

func get(k key) *value {
	mu.Lock()
	defer mu.Unlock()
	var v *value
	if valSafe != nil {
		v = valSafe[k]
	} else if addr, ok := valMap[k]; ok {
		v = (*value)((unsafe.Pointer)(addr))
		v.resurrected = true
	}
	if v != nil {
		return v
	}
	v = k.value()
	if valSafe != nil {
		valSafe[k] = v
	} else {
		runtime.SetFinalizer(v, finalize)
		valMap[k] = uintptr(unsafe.Pointer(v))
	}
	return v
}

func keyFor(cmpVal any) key {
	if s, ok := cmpVal.(string); ok {
		return key{s: s, isString: true}
	}
	return key{cmpVal: cmpVal}
}

func finalize(v *value) {
	mu.Lock()
	defer mu.Unlock()
	if v.resurrected {
		v.resurrected = false
		runtime.SetFinalizer(v, finalize)
		return
	}
	delete(valMap, keyFor(v.cmpVal))
}

var (
	z0    = (*value)(nil)
	z4    = new(value)
	z6noz = new(value)
)

func getByString(s string) *value {
	return get(key{s: s, isString: true})
}
func (ip IP) isZero() bool       { return ip.z == z0 }
func (p ipPrefix) isValid() bool { return !p.ip.isZero() && p.bits <= p.ip.bitLen() }
func (p ipPrefix) isZero() bool  { return p == ipPrefix{} }
func (ip IP) less(ip2 IP) bool   { return ip.compare(ip2) == -1 }
func (ip IP) appendTo4(ret []byte) []byte {
	ret = appendDecimal(ret, ip.v4(0))
	ret = append(ret, '.')
	ret = appendDecimal(ret, ip.v4(1))
	ret = append(ret, '.')
	ret = appendDecimal(ret, ip.v4(2))
	ret = append(ret, '.')
	ret = appendDecimal(ret, ip.v4(3))
	return ret
}

func appendDecimal(b []byte, x uint8) []byte {
	if x >= 100 {
		b = append(b, digits[x/100])
	}
	if x >= 10 {
		b = append(b, digits[x/10%10])
	}
	return append(b, digits[x%10])
}

func appendHex(b []byte, x uint16) []byte {
	if x >= 0x1000 {
		b = append(b, digits[x>>12])
	}
	if x >= 0x100 {
		b = append(b, digits[x>>8&0xf])
	}
	if x >= 0x10 {
		b = append(b, digits[x>>4&0xf])
	}
	return append(b, digits[x&0xf])
}
func ipv6unspecified() IP { return IP{z: z6noz} }
func ipv4(a, b, c, d uint8) IP {
	return IP{
		addr: uint128{0, 0xffff00000000 | uint64(a)<<24 | uint64(b)<<16 | uint64(c)<<8 | uint64(d)},
		z:    z4,
	}
}

func (ip IP) withzone(zone string) IP {
	if !ip.is6() {
		return ip
	}
	if zone == "" {
		ip.z = z6noz
		return ip
	}
	ip.z = getByString(zone)
	return ip
}

func ipv6Raw(addr [16]byte) IP {
	return IP{
		addr: uint128{
			binary.BigEndian.Uint64(addr[:8]),
			binary.BigEndian.Uint64(addr[8:]),
		},
		z: z6noz,
	}
}

func (ip IP) appendTo6(ret []byte) []byte {
	zeroStart, zeroEnd := uint8(255), uint8(255)
	for i := uint8(0); i < 8; i++ {
		j := i
		for j < 8 && ip.v6u16(j) == 0 {
			j++
		}
		if l := j - i; l >= 2 && l > zeroEnd-zeroStart {
			zeroStart, zeroEnd = i, j
		}
	}
	for i := uint8(0); i < 8; i++ {
		if i == zeroStart {
			ret = append(ret, ':', ':')
			i = zeroEnd
			if i >= 8 {
				break
			}
		} else if i > 0 {
			ret = append(ret, ':')
		}
		ret = appendHex(ret, ip.v6u16(i))
	}
	if ip.z != z6noz {
		ret = append(ret, '%')
		ret = append(ret, ip.zone()...)
	}
	return ret
}

func parseipRange(s string) (ipRange, error) {
	var r ipRange
	h := strings.IndexByte(s, '-')
	if h == -1 {
		return r, fmt.Errorf("no hyphen in range %q", s)
	}
	from, to := s[:h], s[h+1:]
	var err error
	r.from, err = parseIP(from)
	if err != nil {
		return r, fmt.Errorf("invalid From IP %q in range %q", from, s)
	}
	r.from = r.from.withoutzone()
	r.to, err = parseIP(to)
	if err != nil {
		return r, fmt.Errorf("invalid To IP %q in range %q", to, s)
	}
	r.to = r.to.withoutzone()
	if !r.isValid() {
		return r, fmt.Errorf("range %v to %v not valid", r.from, r.to)
	}
	return r, nil
}

func (p ipPrefix) AppendTo(b []byte) []byte {
	if p.isZero() {
		return b
	}
	if !p.isValid() {
		return append(b, "invalid ipPrefix"...)
	}
	if p.ip.z == z4 {
		b = p.ip.appendTo4(b)
	} else {
		b = p.ip.appendTo6(b)
	}
	b = append(b, '/')
	b = appendDecimal(b, p.bits)
	return b
}

const digits = "0123456789abcdef"

func (ip IP) v4(i uint8) uint8     { return uint8(ip.addr.lo >> ((3 - i) * 8)) }
func (ip IP) v6u16(i uint8) uint16 { return uint16(*(ip.addr.halves()[(i/4)%2]) >> ((3 - i%4) * 16)) }
func (ip IP) bitLen() uint8 {
	switch ip.z {
	case z0:
		return 0
	case z4:
		return 32
	}
	return 128
}

func (ip IP) zone() string {
	if ip.z == nil {
		return ""
	}
	zone, _ := ip.z.Get().(string)
	return zone
}

func (ip IP) compare(ip2 IP) int {
	f1, f2 := ip.bitLen(), ip2.bitLen()
	if f1 < f2 {
		return -1
	}
	if f1 > f2 {
		return 1
	}
	if hi1, hi2 := ip.addr.hi, ip2.addr.hi; hi1 < hi2 {
		return -1
	} else if hi1 > hi2 {
		return 1
	}
	if lo1, lo2 := ip.addr.lo, ip2.addr.lo; lo1 < lo2 {
		return -1
	} else if lo1 > lo2 {
		return 1
	}
	if ip.is6() {
		za, zb := ip.zone(), ip2.zone()
		if za < zb {
			return -1
		} else if za > zb {
			return 1
		}
	}
	return 0
}

func (r ipRange) prefixes() []ipPrefix {
	return r.AppendPrefixes(nil)
}

func (r ipRange) AppendPrefixes(dst []ipPrefix) []ipPrefix {
	if !r.isValid() {
		return nil
	}
	return appendRangePrefixes(dst, r.prefixFrom128AndBits, r.from.addr, r.to.addr)
}

func (r ipRange) prefixFrom128AndBits(a uint128, xbits uint8) ipPrefix {
	ip := IP{addr: a, z: r.from.z}
	if r.from.is4() {
		xbits -= 12 * 8
	}
	return ipPrefix{ip, xbits}
}

func parseIP(s string) (IP, error) {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '.':
			return parseipv4(s)
		case ':':
			return parseipv6(s)
		case '%':
			return IP{}, parseIPError{in: s, msg: "missing ipv6 address"}
		}
	}
	return IP{}, parseIPError{in: s, msg: "unable to parse IP"}
}

func mustParseIP(s string) IP {
	ip, err := parseIP(s)
	if err != nil {
		panic(err)
	}
	return ip
}

type parseIPError struct {
	in  string
	msg string
	at  string
}

func (err parseIPError) Error() string {
	if err.at != "" {
		return fmt.Sprintf("parseIP(%q): %s (at %q)", err.in, err.msg, err.at)
	}
	return fmt.Sprintf("parseIP(%q): %s", err.in, err.msg)
}

func (ip IP) withoutzone() IP {
	if !ip.is6() {
		return ip
	}
	ip.z = z6noz
	return ip
}

func (r ipRange) isValid() bool {
	return !r.from.isZero() &&
		r.from.z == r.to.z &&
		!r.to.less(r.from)
}

type ipPrefix struct {
	ip   IP
	bits uint8
}

func (p ipPrefix) marshalText() ([]byte, error) {
	var max int
	switch p.ip.z {
	case z0:
	case z4:
		max = len("255.255.255.255/32")
	default:
		max = len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%enp5s0/128")
	}
	b := make([]byte, 0, max)
	b = p.AppendTo(b)
	return b, nil
}

func appendRangePrefixes(dst []ipPrefix, makePrefix prefixMaker, a, b uint128) []ipPrefix {
	common, ok := comparePrefixes(a, b)
	if ok {
		return append(dst, makePrefix(a, common))
	}
	dst = appendRangePrefixes(dst, makePrefix, a, a.bitsSetFrom(common+1))
	dst = appendRangePrefixes(dst, makePrefix, b.bitsClearedFrom(common+1), b)
	return dst
}

func (ip IP) is4() bool {
	return ip.z == z4
}

func (ip IP) is4in6() bool {
	return ip.is6() && ip.addr.hi == 0 && ip.addr.lo>>32 == 0xffff
}

func (ip IP) is6() bool {
	return ip.z != z0 && ip.z != z4
}

func parseipv4(s string) (ip IP, err error) {
	var fields [3]uint8
	var val, pos int
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			val = val*10 + int(s[i]) - '0'
			if val > 255 {
				return IP{}, parseIPError{in: s, msg: "ipv4 field has value >255"}
			}
		} else if s[i] == '.' {
			if i == 0 || i == len(s)-1 || s[i-1] == '.' {
				return IP{}, parseIPError{in: s, msg: "ipv4 field must have at least one digit", at: s[i:]}
			}
			if pos == 3 {
				return IP{}, parseIPError{in: s, msg: "ipv4 address too long"}
			}
			fields[pos] = uint8(val)
			pos++
			val = 0
		} else {
			return IP{}, parseIPError{in: s, msg: "unexpected character", at: s[i:]}
		}
	}
	if pos < 3 {
		return IP{}, parseIPError{in: s, msg: "ipv4 address too short"}
	}
	return ipv4(fields[0], fields[1], fields[2], uint8(val)), nil
}

func parseipv6(in string) (IP, error) {
	s := in
	zone := ""
	i := strings.IndexByte(s, '%')
	if i != -1 {
		s, zone = s[:i], s[i+1:]
		if zone == "" {
			return IP{}, parseIPError{in: in, msg: "zone must be a non-empty string"}
		}
	}
	var ip [16]byte
	ellipsis := -1
	if len(s) >= 2 && s[0] == ':' && s[1] == ':' {
		ellipsis = 0
		s = s[2:]
		if len(s) == 0 {
			return ipv6unspecified().withzone(zone), nil
		}
	}
	i = 0
	for i < 16 {
		off := 0
		acc := uint32(0)
		for ; off < len(s); off++ {
			c := s[off]
			if c >= '0' && c <= '9' {
				acc = (acc << 4) + uint32(c-'0')
			} else if c >= 'a' && c <= 'f' {
				acc = (acc << 4) + uint32(c-'a'+10)
			} else if c >= 'A' && c <= 'F' {
				acc = (acc << 4) + uint32(c-'A'+10)
			} else {
				break
			}
			if acc > math.MaxUint16 {
				return IP{}, parseIPError{in: in, msg: "ipv6 field has value >=2^16", at: s}
			}
		}
		if off == 0 {
			return IP{}, parseIPError{in: in, msg: "each colon-separated field must have at least one digit", at: s}
		}
		if off < len(s) && s[off] == '.' {
			if ellipsis < 0 && i != 12 {
				return IP{}, parseIPError{in: in, msg: "embedded ipv4 address must replace the final 2 fields of the address", at: s}
			}
			if i+4 > 16 {
				return IP{}, parseIPError{in: in, msg: "too many hex fields to fit an embedded ipv4 at the end of the address", at: s}
			}
			ip4, err := parseipv4(s)
			if err != nil {
				return IP{}, parseIPError{in: in, msg: err.Error(), at: s}
			}
			ip[i] = ip4.v4(0)
			ip[i+1] = ip4.v4(1)
			ip[i+2] = ip4.v4(2)
			ip[i+3] = ip4.v4(3)
			s = ""
			i += 4
			break
		}
		ip[i] = byte(acc >> 8)
		ip[i+1] = byte(acc)
		i += 2
		s = s[off:]
		if len(s) == 0 {
			break
		}
		if s[0] != ':' {
			return IP{}, parseIPError{in: in, msg: "unexpected character, want colon", at: s}
		} else if len(s) == 1 {
			return IP{}, parseIPError{in: in, msg: "colon must be followed by more characters", at: s}
		}
		s = s[1:]
		if s[0] == ':' {
			if ellipsis >= 0 {
				return IP{}, parseIPError{in: in, msg: "multiple :: in address", at: s}
			}
			ellipsis = i
			s = s[1:]
			if len(s) == 0 {
				break
			}
		}
	}
	if len(s) != 0 {
		return IP{}, parseIPError{in: in, msg: "trailing garbage after address", at: s}
	}
	if i < 16 {
		if ellipsis < 0 {
			return IP{}, parseIPError{in: in, msg: "address string too short"}
		}
		n := 16 - i
		for j := i - 1; j >= ellipsis; j-- {
			ip[j+n] = ip[j]
		}
		for j := ellipsis + n - 1; j >= ellipsis; j-- {
			ip[j] = 0
		}
	} else if ellipsis >= 0 {
		return IP{}, parseIPError{in: in, msg: "the :: must expand to at least one field of zeros"}
	}
	return ipv6Raw(ip).withzone(zone), nil
}

var mask6 = [...]uint128{
	0:   {0x0000000000000000, 0x0000000000000000},
	1:   {0x8000000000000000, 0x0000000000000000},
	2:   {0xc000000000000000, 0x0000000000000000},
	3:   {0xe000000000000000, 0x0000000000000000},
	4:   {0xf000000000000000, 0x0000000000000000},
	5:   {0xf800000000000000, 0x0000000000000000},
	6:   {0xfc00000000000000, 0x0000000000000000},
	7:   {0xfe00000000000000, 0x0000000000000000},
	8:   {0xff00000000000000, 0x0000000000000000},
	9:   {0xff80000000000000, 0x0000000000000000},
	10:  {0xffc0000000000000, 0x0000000000000000},
	11:  {0xffe0000000000000, 0x0000000000000000},
	12:  {0xfff0000000000000, 0x0000000000000000},
	13:  {0xfff8000000000000, 0x0000000000000000},
	14:  {0xfffc000000000000, 0x0000000000000000},
	15:  {0xfffe000000000000, 0x0000000000000000},
	16:  {0xffff000000000000, 0x0000000000000000},
	17:  {0xffff800000000000, 0x0000000000000000},
	18:  {0xffffc00000000000, 0x0000000000000000},
	19:  {0xffffe00000000000, 0x0000000000000000},
	20:  {0xfffff00000000000, 0x0000000000000000},
	21:  {0xfffff80000000000, 0x0000000000000000},
	22:  {0xfffffc0000000000, 0x0000000000000000},
	23:  {0xfffffe0000000000, 0x0000000000000000},
	24:  {0xffffff0000000000, 0x0000000000000000},
	25:  {0xffffff8000000000, 0x0000000000000000},
	26:  {0xffffffc000000000, 0x0000000000000000},
	27:  {0xffffffe000000000, 0x0000000000000000},
	28:  {0xfffffff000000000, 0x0000000000000000},
	29:  {0xfffffff800000000, 0x0000000000000000},
	30:  {0xfffffffc00000000, 0x0000000000000000},
	31:  {0xfffffffe00000000, 0x0000000000000000},
	32:  {0xffffffff00000000, 0x0000000000000000},
	33:  {0xffffffff80000000, 0x0000000000000000},
	34:  {0xffffffffc0000000, 0x0000000000000000},
	35:  {0xffffffffe0000000, 0x0000000000000000},
	36:  {0xfffffffff0000000, 0x0000000000000000},
	37:  {0xfffffffff8000000, 0x0000000000000000},
	38:  {0xfffffffffc000000, 0x0000000000000000},
	39:  {0xfffffffffe000000, 0x0000000000000000},
	40:  {0xffffffffff000000, 0x0000000000000000},
	41:  {0xffffffffff800000, 0x0000000000000000},
	42:  {0xffffffffffc00000, 0x0000000000000000},
	43:  {0xffffffffffe00000, 0x0000000000000000},
	44:  {0xfffffffffff00000, 0x0000000000000000},
	45:  {0xfffffffffff80000, 0x0000000000000000},
	46:  {0xfffffffffffc0000, 0x0000000000000000},
	47:  {0xfffffffffffe0000, 0x0000000000000000},
	48:  {0xffffffffffff0000, 0x0000000000000000},
	49:  {0xffffffffffff8000, 0x0000000000000000},
	50:  {0xffffffffffffc000, 0x0000000000000000},
	51:  {0xffffffffffffe000, 0x0000000000000000},
	52:  {0xfffffffffffff000, 0x0000000000000000},
	53:  {0xfffffffffffff800, 0x0000000000000000},
	54:  {0xfffffffffffffc00, 0x0000000000000000},
	55:  {0xfffffffffffffe00, 0x0000000000000000},
	56:  {0xffffffffffffff00, 0x0000000000000000},
	57:  {0xffffffffffffff80, 0x0000000000000000},
	58:  {0xffffffffffffffc0, 0x0000000000000000},
	59:  {0xffffffffffffffe0, 0x0000000000000000},
	60:  {0xfffffffffffffff0, 0x0000000000000000},
	61:  {0xfffffffffffffff8, 0x0000000000000000},
	62:  {0xfffffffffffffffc, 0x0000000000000000},
	63:  {0xfffffffffffffffe, 0x0000000000000000},
	64:  {0xffffffffffffffff, 0x0000000000000000},
	65:  {0xffffffffffffffff, 0x8000000000000000},
	66:  {0xffffffffffffffff, 0xc000000000000000},
	67:  {0xffffffffffffffff, 0xe000000000000000},
	68:  {0xffffffffffffffff, 0xf000000000000000},
	69:  {0xffffffffffffffff, 0xf800000000000000},
	70:  {0xffffffffffffffff, 0xfc00000000000000},
	71:  {0xffffffffffffffff, 0xfe00000000000000},
	72:  {0xffffffffffffffff, 0xff00000000000000},
	73:  {0xffffffffffffffff, 0xff80000000000000},
	74:  {0xffffffffffffffff, 0xffc0000000000000},
	75:  {0xffffffffffffffff, 0xffe0000000000000},
	76:  {0xffffffffffffffff, 0xfff0000000000000},
	77:  {0xffffffffffffffff, 0xfff8000000000000},
	78:  {0xffffffffffffffff, 0xfffc000000000000},
	79:  {0xffffffffffffffff, 0xfffe000000000000},
	80:  {0xffffffffffffffff, 0xffff000000000000},
	81:  {0xffffffffffffffff, 0xffff800000000000},
	82:  {0xffffffffffffffff, 0xffffc00000000000},
	83:  {0xffffffffffffffff, 0xffffe00000000000},
	84:  {0xffffffffffffffff, 0xfffff00000000000},
	85:  {0xffffffffffffffff, 0xfffff80000000000},
	86:  {0xffffffffffffffff, 0xfffffc0000000000},
	87:  {0xffffffffffffffff, 0xfffffe0000000000},
	88:  {0xffffffffffffffff, 0xffffff0000000000},
	89:  {0xffffffffffffffff, 0xffffff8000000000},
	90:  {0xffffffffffffffff, 0xffffffc000000000},
	91:  {0xffffffffffffffff, 0xffffffe000000000},
	92:  {0xffffffffffffffff, 0xfffffff000000000},
	93:  {0xffffffffffffffff, 0xfffffff800000000},
	94:  {0xffffffffffffffff, 0xfffffffc00000000},
	95:  {0xffffffffffffffff, 0xfffffffe00000000},
	96:  {0xffffffffffffffff, 0xffffffff00000000},
	97:  {0xffffffffffffffff, 0xffffffff80000000},
	98:  {0xffffffffffffffff, 0xffffffffc0000000},
	99:  {0xffffffffffffffff, 0xffffffffe0000000},
	100: {0xffffffffffffffff, 0xfffffffff0000000},
	101: {0xffffffffffffffff, 0xfffffffff8000000},
	102: {0xffffffffffffffff, 0xfffffffffc000000},
	103: {0xffffffffffffffff, 0xfffffffffe000000},
	104: {0xffffffffffffffff, 0xffffffffff000000},
	105: {0xffffffffffffffff, 0xffffffffff800000},
	106: {0xffffffffffffffff, 0xffffffffffc00000},
	107: {0xffffffffffffffff, 0xffffffffffe00000},
	108: {0xffffffffffffffff, 0xfffffffffff00000},
	109: {0xffffffffffffffff, 0xfffffffffff80000},
	110: {0xffffffffffffffff, 0xfffffffffffc0000},
	111: {0xffffffffffffffff, 0xfffffffffffe0000},
	112: {0xffffffffffffffff, 0xffffffffffff0000},
	113: {0xffffffffffffffff, 0xffffffffffff8000},
	114: {0xffffffffffffffff, 0xffffffffffffc000},
	115: {0xffffffffffffffff, 0xffffffffffffe000},
	116: {0xffffffffffffffff, 0xfffffffffffff000},
	117: {0xffffffffffffffff, 0xfffffffffffff800},
	118: {0xffffffffffffffff, 0xfffffffffffffc00},
	119: {0xffffffffffffffff, 0xfffffffffffffe00},
	120: {0xffffffffffffffff, 0xffffffffffffff00},
	121: {0xffffffffffffffff, 0xffffffffffffff80},
	122: {0xffffffffffffffff, 0xffffffffffffffc0},
	123: {0xffffffffffffffff, 0xffffffffffffffe0},
	124: {0xffffffffffffffff, 0xfffffffffffffff0},
	125: {0xffffffffffffffff, 0xfffffffffffffff8},
	126: {0xffffffffffffffff, 0xfffffffffffffffc},
	127: {0xffffffffffffffff, 0xfffffffffffffffe},
	128: {0xffffffffffffffff, 0xffffffffffffffff},
}
