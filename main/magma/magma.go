package magma

import (
	"crisp/main/kdf"
	"crisp/main/randomNumber"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/pbkdf2"
)

var sBox = [8][16]byte{
	{1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2},
	{8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7},
	{5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0},
	{7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12},
	{12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
	{11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0},
	{6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
	{12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1}}

type subkey struct {
	key []byte
}

type Subkeys struct {
	subkeys [32]subkey
}

func xorBlock(blockOne []byte, blockTwo []byte) []byte {
	i := 0
	outBlock := make([]byte, 4)
	for i < 4 {
		outBlock[i] = blockOne[i] ^ blockTwo[i]
		i++
	}
	return outBlock
}

func mod32(blockOne []byte, blockTwo []byte) []byte {
	var internal uint64
	outputBlock := make([]byte, 4)
	for i := 3; i >= 0; i-- {
		internal = uint64(blockOne[i]+blockTwo[i]) + (internal >> 8)
		outputBlock[i] = byte(internal & 0xff)
	}
	return outputBlock
}

func changeT(inputBlock []byte) []byte {
	var firstPart, secPart byte
	i := 0
	outputBlock := make([]byte, 4)
	for i < 4 {
		firstPart = (inputBlock[i] & 0xf0) >> 4
		secPart = inputBlock[i] & 0x0f
		firstPart = sBox[i*2][firstPart]
		secPart = sBox[i*2+1][secPart]
		outputBlock[i] = (firstPart << 4) | secPart
		i++
	}
	return outputBlock
}

func GenSubKeys(key []byte) (*Subkeys, error) {
	if len(key) != 32 {
		return nil, errors.New("Key is not supported")
	}
	s := &Subkeys{}
	d := 0
	i := 0
	for i < 24 {
		copyKey(key, &s.subkeys[i], d)
		d += 4
		if d > 28 {
			d = 0
		}
		i++
	}
	d = 32
	for i < 32 {
		copyKeyRev(key, &s.subkeys[i], d)
		d -= 4
		i++
	}
	return s, nil
}

//копирование до 24 байта
func copyKey(key []byte, s *subkey, dist int) subkey {
	s.key = key[dist : dist+4]
	return *s
}

//копирование до 32 байта
func copyKeyRev(key []byte, s *subkey, dist int) subkey {
	s.key = key[dist-4 : dist]
	return *s
}

func g(subKey subkey, block []byte) []byte {
	intermediateBlock := make([]byte, 4)
	outBlock := make([]byte, 4)
	var outData32 uint32

	intermediateBlock = mod32(block, subKey.key)

	intermediateBlock = changeT(intermediateBlock)

	outData32 = uint32(intermediateBlock[0])
	outData32 = (outData32 << 8) + uint32(intermediateBlock[1])
	outData32 = (outData32 << 8) + uint32(intermediateBlock[2])
	outData32 = (outData32 << 8) + uint32(intermediateBlock[3])

	outData32 = (outData32 << 11) | (outData32 >> 21)

	outBlock[3] = byte(outData32)
	outBlock[2] = byte(outData32 >> 8)
	outBlock[1] = byte(outData32 >> 16)
	outBlock[0] = byte(outData32 >> 24)

	return outBlock
}

func changeG(subKey subkey, block []byte) []byte {
	rightSideBlock := make([]byte, 4)
	leftSideBlock := make([]byte, 4)
	intermediateBlock := make([]byte, 4)

	for i := 0; i < 4; i++ {
		rightSideBlock[i] = block[4+i]
		leftSideBlock[i] = block[i]
	}

	intermediateBlock = g(subKey, rightSideBlock)
	intermediateBlock = xorBlock(leftSideBlock, intermediateBlock)

	for i := 0; i < 4; i++ {
		leftSideBlock[i] = rightSideBlock[i]

		rightSideBlock[i] = intermediateBlock[i]
	}

	for i := 0; i < 4; i++ {
		block[i] = leftSideBlock[i]
		block[4+i] = rightSideBlock[i]
	}
	return block
}

func changeGFin(subKey subkey, block []byte) []byte {
	rightSideBlock := make([]byte, 4)
	leftSideBlock := make([]byte, 4)
	intermediateBlock := make([]byte, 4)

	for i := 0; i < 4; i++ {
		rightSideBlock[i] = block[4+i]
		leftSideBlock[i] = block[i]
	}

	intermediateBlock = g(subKey, rightSideBlock)
	intermediateBlock = xorBlock(leftSideBlock, intermediateBlock)

	for i := 0; i < 4; i++ {
		leftSideBlock[i] = intermediateBlock[i]
	}

	for i := 0; i < 4; i++ {
		block[i] = leftSideBlock[i]
		block[4+i] = rightSideBlock[i]
	}
	return block
}

func (s *Subkeys) EncryptBlock(block []byte) ([]byte, error) {
	if len(block) != 8 {
		return nil, errors.New("block != blockLength")
	}

	block = changeG(s.subkeys[0], block)

	for i := 1; i < 31; i++ {
		block = changeG(s.subkeys[i], block)
	}
	block = changeGFin(s.subkeys[31], block)

	return block, nil
}

func (s *Subkeys) DecryptBlock(block []byte) []byte {
	block = changeG(s.subkeys[31], block)

	for i := 30; i > 0; i-- {
		block = changeG(s.subkeys[i], block)
	}
	block = changeGFin(s.subkeys[0], block)

	return block
}

// смена подключей после вызова acpkm
func (s *Subkeys) ChangeKey() (*Subkeys, error) {
	kj, err := s.acpkm()
	newS, err := GenSubKeys(kj)
	if err != nil {
		return nil, err
	}
	return newS, nil
}

func (s *Subkeys) acpkm() ([]byte, error) { //todo урезать длину
	newK := make([]byte, 32)
	var err error
	part1, part2, part3, part4 := getConstD()

	part1, err = s.EncryptBlock(part1)
	newK = append(newK, part1...)

	part2, err = s.EncryptBlock(part2)
	newK = append(newK, part2...)

	part3, err = s.EncryptBlock(part3)
	newK = append(newK, part3...)

	part4, err = s.EncryptBlock(part4)

	if err != nil {
		return nil, err
	}
	newK = append(newK, part4...)
	return newK[32:], nil
}

func getConstD() ([]byte, []byte, []byte, []byte) {
	return []byte{128, 129, 130, 131, 132, 133, 134, 135}, []byte{136, 137, 138, 139, 140, 141, 142, 143},
		[]byte{144, 145, 146, 147, 148, 149, 150, 151}, []byte{152, 153, 154, 155, 156, 157, 158, 159}
}

func (s *Subkeys) ClearingMemory() *Subkeys {
	s = &Subkeys{}
	return s
}

func ChangeOldKeyToNewKey(old []byte) ([]byte, error) {
	//hash := sha256.New
	//hkdf := hkdf.New(hash, old, nil, nil)

	//key := make([]byte, 32)
	//if _, err := io.ReadFull(hkdf, key); err != nil {
	//	return nil, err
	//}
	salt := []byte{}
	k := kdf.New()
	key, err := k.KDF(old, salt)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (s *Subkeys) RotateSubkeys(key []byte) (*Subkeys, error) {
	newS, err := GenSubKeys(key)
	if err != nil {
		return nil, err
	}
	return newS, nil
}

// смена ключа через n блоков
func RotateKeyCounter(count int) int {
	switch count {
	case 10:
		return 10
	case 1000:
		return 100
	case 10000:
		return 1000
	default:
		return 100
	}
	return 0
}

func intToSlice(number uint32) []byte {
	s := make([]byte, 4)
	binary.BigEndian.PutUint32(s, number)
	return s
}

func concatenation(iv, ctr []byte) []byte {
	iv = append(iv, ctr...)
	return iv
}

func PasswordToKey(password []byte) []byte {
	hash := sha256.New()
	hash.Write(password)
	salt := hex.EncodeToString(hash.Sum(nil))

	key := pbkdf2.Key(password, []byte(salt), 4096, 32, sha256.New)
	return key
}

func GenIV() []byte {
	/*rand.Seed(time.Now().UnixNano())
	min := 0
	max := 255
	iv := make([]byte, 4)

	for i := range iv {
		iv[i] = byte(rand.Intn(max-min+1) + min)
	}*/
	r := randomNumber.ISAAC{}
	t := randomNumber.Test{}
	flag := false
	var iv []byte
	for flag == false {
		iv = r.GenSeq()
		flag, _ = t.CheckSeq(iv)
	}
	return iv
}

// Полный раунд ctr-acpkm
func RoundCipher(s *Subkeys, plainBlock, iv []byte, counter uint32) (*Subkeys, []byte, error) {
	var err error
	ctr := concatenation(iv, intToSlice(counter))

	s, err = s.ChangeKey()
	if err != nil {
		return nil, nil, err
	}

	ctr, err = s.EncryptBlock(ctr)
	if err != nil {
		return nil, nil, err
	}

	outBlock := xor(plainBlock, ctr)
	return s, outBlock, nil
}

func xor(left, right []byte) []byte {
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[i] = left[i] ^ right[i]
	}
	return out
}
