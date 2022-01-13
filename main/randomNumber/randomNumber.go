package randomNumber

import (
	"bytes"
	"encoding/binary"
	"math"
	"strconv"
	"strings"
)

const (
	numBitsInSeq = 8 * 16
)

type Test struct {
}

type ISAAC struct {
	randrsl [256]uint32
	randcnt uint32

	mm         [256]uint32
	aa, bb, cc uint32
}

func (t *Test) CheckSeq(seq []byte) (bool, error) {
	flagR, err := rowTest(seq)
	if err != nil{
		return false, err
	}
	flagB := bitsTest(seq)
	if flagR == true && flagB == true{
		return true, nil
	}
	return false, nil
}

func (is *ISAAC) GenSeq() []byte {
	seq := make([]byte, 4)
	n := 0
	is.randInit(true)
	is.iSaac()
	for j := 0; j < 4; j++ {
		seq[n] = byte(is.randrsl[j])
		n++
	}
	return seq
}

func (is *ISAAC) iSaac() {
	is.cc = is.cc + 1
	is.bb = is.bb + is.cc

	for i := 0; i < 256; i++ {
		x := is.mm[i]
		switch i % 4 {
		case 0:
			is.aa = is.aa ^ (is.aa << 13)
		case 1:
			is.aa = is.aa ^ (is.aa >> 6)
		case 2:
			is.aa = is.aa ^ (is.aa << 2)
		case 3:
			is.aa = is.aa ^ (is.aa >> 16)
		}
		is.aa = is.mm[(i+128)%256] + is.aa
		y := is.mm[(x>>2)%256] + is.aa + is.bb
		is.mm[i] = y
		is.bb = is.mm[(y>>10)%256] + x
		is.randrsl[i] = is.bb
	}
}

func mix(a, b, c, d, e, f, g, h uint32) (uint32, uint32, uint32, uint32, uint32, uint32, uint32, uint32) {
	a ^= b << 11
	d += a
	b += c
	b ^= c >> 2
	e += b
	c += d
	c ^= d << 8
	f += c
	d += e
	d ^= e >> 16
	g += d
	e += f
	e ^= f << 10
	h += e
	f += g
	f ^= g >> 4
	a += f
	g += h
	g ^= h << 8
	b += g
	h += a
	h ^= a >> 9
	c += h
	a += b
	return a, b, c, d, e, f, g, h
}

func (is *ISAAC) randInit(flag bool) {
	var a, b, c, d, e, f, g, h uint32
	a, b, c, d, e, f, g, h = 0x9e3779b9, 0x9e3779b9, 0x9e3779b9, 0x9e3779b9, 0x9e3779b9, 0x9e3779b9, 0x9e3779b9, 0x9e3779b9

	for i := 0; i < 4; i++ {
		a, b, c, d, e, f, g, h = mix(a, b, c, d, e, f, g, h)
	}

	for i := 0; i < 256; i += 8 {
		if flag {
			a += is.randrsl[i]
			b += is.randrsl[i+1]
			c += is.randrsl[i+2]
			d += is.randrsl[i+3]
			e += is.randrsl[i+4]
			f += is.randrsl[i+5]
			g += is.randrsl[i+6]
			h += is.randrsl[i+7]
		}
		a, b, c, d, e, f, g, h = mix(a, b, c, d, e, f, g, h)
		is.mm[i] = a
		is.mm[i+1] = b
		is.mm[i+2] = c
		is.mm[i+3] = d
		is.mm[i+4] = e
		is.mm[i+5] = f
		is.mm[i+6] = g
		is.mm[i+7] = h
	}

	if flag {
		for i := 0; i < 256; i += 8 {
			a += is.mm[i]
			b += is.mm[i+1]
			c += is.mm[i+2]
			d += is.mm[i+3]
			e += is.mm[i+4]
			f += is.mm[i+5]
			g += is.mm[i+6]
			h += is.mm[i+7]
			a, b, c, d, e, f, g, h = mix(a, b, c, d, e, f, g, h)
			is.mm[i] = a
			is.mm[i+1] = b
			is.mm[i+2] = c
			is.mm[i+3] = d
			is.mm[i+4] = e
			is.mm[i+5] = f
			is.mm[i+6] = g
			is.mm[i+7] = h
		}
	}

	is.iSaac()
	is.randcnt = 256
}

func (is *ISAAC) seed(key string) {
	keyBuf := bytes.NewBuffer([]byte(key))

	var padding = 0
	if keyBuf.Len()%4 != 0 {
		padding = 4 - (keyBuf.Len() % 4)
	}
	for i := 0; i < padding; i++ {
		keyBuf.WriteByte(0x00)
	}

	var count = keyBuf.Len() / 4
	for i := 0; i < count; i++ {
		if i == len(is.randrsl) {
			break
		}

		var num uint32
		if err := binary.Read(keyBuf, binary.LittleEndian, &num); err == nil {
			is.randrsl[i] = num
		}
	}
	is.randInit(true)
}

func (is *ISAAC) rand() (number uint32) {
	is.randcnt--
	number = is.randrsl[is.randcnt]
	if is.randcnt == 0 {
		is.iSaac()
		is.randcnt = 256
	}
	return number
}

func rowTest(seq []byte) (bool, error) {
	count := 0
	for i := range seq {
		count += countBits(seq[i])
	}

	pi := float64(count) / float64(numBitsInSeq)

	if !(math.Abs(float64(pi)-0.5) < (2 / math.Sqrt(numBitsInSeq))) {
		return false, nil
	}

	v, err := v_seq(seq)
	if err != nil {
		return false, err
	}

	p := p_val(v, pi)
	if p >= 0.01 {
		return true, nil
	}
	return false, nil

}

func p_val(v int , pi float64) float64 {
	num := math.Abs(float64(v) - 2*numBitsInSeq*pi*(1-pi))
	sq := math.Sqrt(2 * numBitsInSeq)
	den := float64(2) * sq * float64(pi) * float64(1-pi)

	res := math.Erfc(num / den)
	return res
}

func v_seq(seq []byte) (int, error) {
	temp := ""
	count := 0
	for i := range seq {
		seqb, err := seqBinary(seq[i])

		if err != nil {
			return 0, err
		}

		for j := 0; j < 7; j++ {
			if (i != 0) && (i != 7) && (j == 0) {
				if !(seqb[0] == temp) {
					count++
				}
			}

			if !(seqb[j] == seqb[j+1]) {
				count++
			}

			if j+1 == 7 {
				temp = seqb[7]
			}
		}
	}
	return count, nil
}

func seqBinary(s byte) ([]string, error) {
	bin, err := ConvertBinary(strconv.Itoa(int(s)), 10, 2)
	if err != nil {
		return nil, err
	}
	seqi := strings.Split(bin, "")
	byteSeqBin := make([]string, 8)
	j := 0
	for i := 7; i >= 0; i-- {

		if len(seqi) <= i {
			byteSeqBin[i] = "0"
		} else {
			byteSeqBin[i] = seqi[j]
			j++
		}
	}
	return byteSeqBin, nil
}

func ConvertBinary(val string, base, toBase int) (string, error) {
	i, err := strconv.ParseInt(val, base, 64)
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(i, toBase), nil
}

func bitsTest(seq []byte) bool {
	count := 0
	for i := range seq {
		count += countBits(seq[i])
	}

	s := float64(count - (numBitsInSeq - count))
	s_obs := s / math.Sqrt(numBitsInSeq)
	p_value := math.Erfc(s_obs / math.Sqrt(2))
	if p_value > 0.01 {
		return true
	} else {
		return false
	}
}

func countBits(n byte) int {
	count := 0
	for n != 0 {
		count++
		n = n & (n - 1)
	}
	return count
}
