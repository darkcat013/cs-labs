package ciphers

import (
	"encoding/hex"
	"errors"
	"strings"
)

// BlockSize is the serpent block size in bytes.
const BlockSize = 16

const phi = 0x9e3779b9 // The Serpent phi constant (sqrt(5) - 1) * 2**31

// The 132 32 bit subkeys of serpent
type subkeys [132]uint32

type Serpent struct {
	KeyString string
}

var errKeySize = errors.New("invalid key size")

func (sr Serpent) EncryptMessage(s string) string {
	str, err := newSerpentCipher([]byte(sr.KeyString))
	if err != nil {
		panic(err)
	}

	var result string
	for i := 0; i < len(s); i += BlockSize {
		cpt := make([]byte, BlockSize)
		if i+BlockSize > len(s) {
			for len(s) < i+BlockSize {
				s += string(0x00)
			}
		}
		str.encrypt(cpt, []byte(s[i:i+BlockSize]))
		result += hex.EncodeToString(cpt)
	}
	return result
}

func (sr Serpent) DecryptMessage(s string) string {
	str, err := newSerpentCipher([]byte(sr.KeyString))
	if err != nil {
		panic(err)
	}

	cpt, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}

	var result string
	for i := 0; i < len(cpt); i += BlockSize {
		plx := make([]byte, BlockSize)
		if i+BlockSize > len(cpt) {
			for len(cpt) < i+BlockSize {
				cpt = append(cpt, 0x00)
			}
		}
		str.decrypt(plx, cpt[i:i+BlockSize])
		result += string(plx)
	}
	return strings.Trim(result, string(0x00))
}

// The key argument must be 128, 192 or 256 bit (16, 24, 32 byte).
func newSerpentCipher(key []byte) (*subkeys, error) {
	if k := len(key); k != 16 && k != 24 && k != 32 {
		return nil, errKeySize
	}
	s := &subkeys{}
	s.keySchedule(key)
	return s, nil
}

func (s *subkeys) encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("src buffer to small")
	}
	if len(dst) < BlockSize {
		panic("dst buffer to small")
	}
	encryptBlock(dst, src, s)
}

func (s *subkeys) decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("src buffer to small")
	}
	if len(dst) < BlockSize {
		panic("dst buffer to small")
	}
	decryptBlock(dst, src, s)
}

// The key schedule of serpent.
func (s *subkeys) keySchedule(key []byte) {
	var k [16]uint32
	j := 0
	for i := 0; i+4 <= len(key); i += 4 {
		k[j] = uint32(key[i]) | uint32(key[i+1])<<8 | uint32(key[i+2])<<16 | uint32(key[i+3])<<24
		j++
	}
	if j < 8 {
		k[j] = 1
	}

	for i := 8; i < 16; i++ {
		x := k[i-8] ^ k[i-5] ^ k[i-3] ^ k[i-1] ^ phi ^ uint32(i-8)
		k[i] = (x << 11) | (x >> 21)
		s[i-8] = k[i]
	}
	for i := 8; i < 132; i++ {
		x := s[i-8] ^ s[i-5] ^ s[i-3] ^ s[i-1] ^ phi ^ uint32(i)
		s[i] = (x << 11) | (x >> 21)
	}

	sb3(&s[0], &s[1], &s[2], &s[3])
	sb2(&s[4], &s[5], &s[6], &s[7])
	sb1(&s[8], &s[9], &s[10], &s[11])
	sb0(&s[12], &s[13], &s[14], &s[15])
	sb7(&s[16], &s[17], &s[18], &s[19])
	sb6(&s[20], &s[21], &s[22], &s[23])
	sb5(&s[24], &s[25], &s[26], &s[27])
	sb4(&s[28], &s[29], &s[30], &s[31])

	sb3(&s[32], &s[33], &s[34], &s[35])
	sb2(&s[36], &s[37], &s[38], &s[39])
	sb1(&s[40], &s[41], &s[42], &s[43])
	sb0(&s[44], &s[45], &s[46], &s[47])
	sb7(&s[48], &s[49], &s[50], &s[51])
	sb6(&s[52], &s[53], &s[54], &s[55])
	sb5(&s[56], &s[57], &s[58], &s[59])
	sb4(&s[60], &s[61], &s[62], &s[63])

	sb3(&s[64], &s[65], &s[66], &s[67])
	sb2(&s[68], &s[69], &s[70], &s[71])
	sb1(&s[72], &s[73], &s[74], &s[75])
	sb0(&s[76], &s[77], &s[78], &s[79])
	sb7(&s[80], &s[81], &s[82], &s[83])
	sb6(&s[84], &s[85], &s[86], &s[87])
	sb5(&s[88], &s[89], &s[90], &s[91])
	sb4(&s[92], &s[93], &s[94], &s[95])

	sb3(&s[96], &s[97], &s[98], &s[99])
	sb2(&s[100], &s[101], &s[102], &s[103])
	sb1(&s[104], &s[105], &s[106], &s[107])
	sb0(&s[108], &s[109], &s[110], &s[111])
	sb7(&s[112], &s[113], &s[114], &s[115])
	sb6(&s[116], &s[117], &s[118], &s[119])
	sb5(&s[120], &s[121], &s[122], &s[123])
	sb4(&s[124], &s[125], &s[126], &s[127])

	sb3(&s[128], &s[129], &s[130], &s[131])
}

func encryptBlock(dst, src []byte, sk *subkeys) {
	// Transform the input block to 4 x 32 bit registers
	r0 := uint32(src[0]) | uint32(src[1])<<8 | uint32(src[2])<<16 | uint32(src[3])<<24
	r1 := uint32(src[4]) | uint32(src[5])<<8 | uint32(src[6])<<16 | uint32(src[7])<<24
	r2 := uint32(src[8]) | uint32(src[9])<<8 | uint32(src[10])<<16 | uint32(src[11])<<24
	r3 := uint32(src[12]) | uint32(src[13])<<8 | uint32(src[14])<<16 | uint32(src[15])<<24

	// Encrypt the block with the 132 sub-keys and 8 S-Boxes
	r0, r1, r2, r3 = r0^sk[0], r1^sk[1], r2^sk[2], r3^sk[3]
	sb0(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[4], r1^sk[5], r2^sk[6], r3^sk[7]
	sb1(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[8], r1^sk[9], r2^sk[10], r3^sk[11]
	sb2(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[12], r1^sk[13], r2^sk[14], r3^sk[15]
	sb3(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[16], r1^sk[17], r2^sk[18], r3^sk[19]
	sb4(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[20], r1^sk[21], r2^sk[22], r3^sk[23]
	sb5(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[24], r1^sk[25], r2^sk[26], r3^sk[27]
	sb6(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[28], r1^sk[29], r2^sk[30], r3^sk[31]
	sb7(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)

	r0, r1, r2, r3 = r0^sk[32], r1^sk[33], r2^sk[34], r3^sk[35]
	sb0(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[36], r1^sk[37], r2^sk[38], r3^sk[39]
	sb1(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[40], r1^sk[41], r2^sk[42], r3^sk[43]
	sb2(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[44], r1^sk[45], r2^sk[46], r3^sk[47]
	sb3(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[48], r1^sk[49], r2^sk[50], r3^sk[51]
	sb4(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[52], r1^sk[53], r2^sk[54], r3^sk[55]
	sb5(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[56], r1^sk[57], r2^sk[58], r3^sk[59]
	sb6(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[60], r1^sk[61], r2^sk[62], r3^sk[63]
	sb7(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)

	r0, r1, r2, r3 = r0^sk[64], r1^sk[65], r2^sk[66], r3^sk[67]
	sb0(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[68], r1^sk[69], r2^sk[70], r3^sk[71]
	sb1(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[72], r1^sk[73], r2^sk[74], r3^sk[75]
	sb2(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[76], r1^sk[77], r2^sk[78], r3^sk[79]
	sb3(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[80], r1^sk[81], r2^sk[82], r3^sk[83]
	sb4(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[84], r1^sk[85], r2^sk[86], r3^sk[87]
	sb5(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[88], r1^sk[89], r2^sk[90], r3^sk[91]
	sb6(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[92], r1^sk[93], r2^sk[94], r3^sk[95]
	sb7(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)

	r0, r1, r2, r3 = r0^sk[96], r1^sk[97], r2^sk[98], r3^sk[99]
	sb0(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[100], r1^sk[101], r2^sk[102], r3^sk[103]
	sb1(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[104], r1^sk[105], r2^sk[106], r3^sk[107]
	sb2(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[108], r1^sk[109], r2^sk[110], r3^sk[111]
	sb3(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[112], r1^sk[113], r2^sk[114], r3^sk[115]
	sb4(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[116], r1^sk[117], r2^sk[118], r3^sk[119]
	sb5(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[120], r1^sk[121], r2^sk[122], r3^sk[123]
	sb6(&r0, &r1, &r2, &r3)
	linear(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[124], r1^sk[125], r2^sk[126], r3^sk[127]
	sb7(&r0, &r1, &r2, &r3)

	// whitening
	r0 ^= sk[128]
	r1 ^= sk[129]
	r2 ^= sk[130]
	r3 ^= sk[131]

	// write the encrypted block to the output

	dst[0] = byte(r0)
	dst[1] = byte(r0 >> 8)
	dst[2] = byte(r0 >> 16)
	dst[3] = byte(r0 >> 24)
	dst[4] = byte(r1)
	dst[5] = byte(r1 >> 8)
	dst[6] = byte(r1 >> 16)
	dst[7] = byte(r1 >> 24)
	dst[8] = byte(r2)
	dst[9] = byte(r2 >> 8)
	dst[10] = byte(r2 >> 16)
	dst[11] = byte(r2 >> 24)
	dst[12] = byte(r3)
	dst[13] = byte(r3 >> 8)
	dst[14] = byte(r3 >> 16)
	dst[15] = byte(r3 >> 24)
}

// Decrypts one block with the given 132 sub-keys sk.
func decryptBlock(dst, src []byte, sk *subkeys) {
	// Transform the input block to 4 x 32 bit registers
	r0 := uint32(src[0]) | uint32(src[1])<<8 | uint32(src[2])<<16 | uint32(src[3])<<24
	r1 := uint32(src[4]) | uint32(src[5])<<8 | uint32(src[6])<<16 | uint32(src[7])<<24
	r2 := uint32(src[8]) | uint32(src[9])<<8 | uint32(src[10])<<16 | uint32(src[11])<<24
	r3 := uint32(src[12]) | uint32(src[13])<<8 | uint32(src[14])<<16 | uint32(src[15])<<24

	// undo whitening
	r0 ^= sk[128]
	r1 ^= sk[129]
	r2 ^= sk[130]
	r3 ^= sk[131]

	// Decrypt the block with the 132 sub-keys and 8 S-Boxes
	sb7Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[124], r1^sk[125], r2^sk[126], r3^sk[127]
	linearInv(&r0, &r1, &r2, &r3)
	sb6Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[120], r1^sk[121], r2^sk[122], r3^sk[123]
	linearInv(&r0, &r1, &r2, &r3)
	sb5Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[116], r1^sk[117], r2^sk[118], r3^sk[119]
	linearInv(&r0, &r1, &r2, &r3)
	sb4Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[112], r1^sk[113], r2^sk[114], r3^sk[115]
	linearInv(&r0, &r1, &r2, &r3)
	sb3Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[108], r1^sk[109], r2^sk[110], r3^sk[111]
	linearInv(&r0, &r1, &r2, &r3)
	sb2Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[104], r1^sk[105], r2^sk[106], r3^sk[107]
	linearInv(&r0, &r1, &r2, &r3)
	sb1Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[100], r1^sk[101], r2^sk[102], r3^sk[103]
	linearInv(&r0, &r1, &r2, &r3)
	sb0Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[96], r1^sk[97], r2^sk[98], r3^sk[99]
	linearInv(&r0, &r1, &r2, &r3)

	sb7Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[92], r1^sk[93], r2^sk[94], r3^sk[95]
	linearInv(&r0, &r1, &r2, &r3)
	sb6Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[88], r1^sk[89], r2^sk[90], r3^sk[91]
	linearInv(&r0, &r1, &r2, &r3)
	sb5Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[84], r1^sk[85], r2^sk[86], r3^sk[87]
	linearInv(&r0, &r1, &r2, &r3)
	sb4Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[80], r1^sk[81], r2^sk[82], r3^sk[83]
	linearInv(&r0, &r1, &r2, &r3)
	sb3Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[76], r1^sk[77], r2^sk[78], r3^sk[79]
	linearInv(&r0, &r1, &r2, &r3)
	sb2Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[72], r1^sk[73], r2^sk[74], r3^sk[75]
	linearInv(&r0, &r1, &r2, &r3)
	sb1Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[68], r1^sk[69], r2^sk[70], r3^sk[71]
	linearInv(&r0, &r1, &r2, &r3)
	sb0Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[64], r1^sk[65], r2^sk[66], r3^sk[67]
	linearInv(&r0, &r1, &r2, &r3)

	sb7Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[60], r1^sk[61], r2^sk[62], r3^sk[63]
	linearInv(&r0, &r1, &r2, &r3)
	sb6Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[56], r1^sk[57], r2^sk[58], r3^sk[59]
	linearInv(&r0, &r1, &r2, &r3)
	sb5Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[52], r1^sk[53], r2^sk[54], r3^sk[55]
	linearInv(&r0, &r1, &r2, &r3)
	sb4Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[48], r1^sk[49], r2^sk[50], r3^sk[51]
	linearInv(&r0, &r1, &r2, &r3)
	sb3Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[44], r1^sk[45], r2^sk[46], r3^sk[47]
	linearInv(&r0, &r1, &r2, &r3)
	sb2Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[40], r1^sk[41], r2^sk[42], r3^sk[43]
	linearInv(&r0, &r1, &r2, &r3)
	sb1Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[36], r1^sk[37], r2^sk[38], r3^sk[39]
	linearInv(&r0, &r1, &r2, &r3)
	sb0Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[32], r1^sk[33], r2^sk[34], r3^sk[35]
	linearInv(&r0, &r1, &r2, &r3)

	sb7Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[28], r1^sk[29], r2^sk[30], r3^sk[31]
	linearInv(&r0, &r1, &r2, &r3)
	sb6Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[24], r1^sk[25], r2^sk[26], r3^sk[27]
	linearInv(&r0, &r1, &r2, &r3)
	sb5Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[20], r1^sk[21], r2^sk[22], r3^sk[23]
	linearInv(&r0, &r1, &r2, &r3)
	sb4Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[16], r1^sk[17], r2^sk[18], r3^sk[19]
	linearInv(&r0, &r1, &r2, &r3)
	sb3Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[12], r1^sk[13], r2^sk[14], r3^sk[15]
	linearInv(&r0, &r1, &r2, &r3)
	sb2Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[8], r1^sk[9], r2^sk[10], r3^sk[11]
	linearInv(&r0, &r1, &r2, &r3)
	sb1Inv(&r0, &r1, &r2, &r3)
	r0, r1, r2, r3 = r0^sk[4], r1^sk[5], r2^sk[6], r3^sk[7]
	linearInv(&r0, &r1, &r2, &r3)
	sb0Inv(&r0, &r1, &r2, &r3)

	r0 ^= sk[0]
	r1 ^= sk[1]
	r2 ^= sk[2]
	r3 ^= sk[3]

	// write the decrypted block to the output
	dst[0] = byte(r0)
	dst[1] = byte(r0 >> 8)
	dst[2] = byte(r0 >> 16)
	dst[3] = byte(r0 >> 24)
	dst[4] = byte(r1)
	dst[5] = byte(r1 >> 8)
	dst[6] = byte(r1 >> 16)
	dst[7] = byte(r1 >> 24)
	dst[8] = byte(r2)
	dst[9] = byte(r2 >> 8)
	dst[10] = byte(r2 >> 16)
	dst[11] = byte(r2 >> 24)
	dst[12] = byte(r3)
	dst[13] = byte(r3 >> 8)
	dst[14] = byte(r3 >> 16)
	dst[15] = byte(r3 >> 24)
}

// The linear transformation of serpent
// This version, tries not to minimize the
// number of registers, but maximize parallism.
func linear(v0, v1, v2, v3 *uint32) {
	t0 := ((*v0 << 13) | (*v0 >> (32 - 13)))
	t2 := ((*v2 << 3) | (*v2 >> (32 - 3)))
	t1 := *v1 ^ t0 ^ t2
	t3 := *v3 ^ t2 ^ (t0 << 3)
	*v1 = (t1 << 1) | (t1 >> (32 - 1))
	*v3 = (t3 << 7) | (t3 >> (32 - 7))
	t0 ^= *v1 ^ *v3
	t2 ^= *v3 ^ (*v1 << 7)
	*v0 = (t0 << 5) | (t0 >> (32 - 5))
	*v2 = (t2 << 22) | (t2 >> (32 - 22))
}

// The inverse linear transformation of serpent
// This version, tries not to minimize the
// number of registers, but maximize parallism.
func linearInv(v0, v1, v2, v3 *uint32) {
	t2 := (*v2 >> 22) | (*v2 << (32 - 22))
	t0 := (*v0 >> 5) | (*v0 << (32 - 5))
	t2 ^= *v3 ^ (*v1 << 7)
	t0 ^= *v1 ^ *v3
	t3 := (*v3 >> 7) | (*v3 << (32 - 7))
	t1 := (*v1 >> 1) | (*v1 << (32 - 1))
	*v3 = t3 ^ t2 ^ (t0 << 3)
	*v1 = t1 ^ t0 ^ t2
	*v2 = (t2 >> 3) | (t2 << (32 - 3))
	*v0 = (t0 >> 13) | (t0 << (32 - 13))
}

// The following functions sb0,sb1, ..., sb7 represent the 8 Serpent S-Boxes.
// sb0Inv til sb7Inv are the inverse functions (e.g. sb0Inv is the Inverse to sb0
// and vice versa).
// The S-Boxes differ from the original Serpent definitions. This is for
// optimisation. The functions use the Serpent S-Box improvements for (non x86)
// from Dr. B. R. Gladman and Sam Simpson.

// S-Box 0
func sb0(r0, r1, r2, r3 *uint32) {
	t0 := *r0 ^ *r3
	t1 := *r2 ^ t0
	t2 := *r1 ^ t1
	*r3 = (*r0 & *r3) ^ t2
	t3 := *r0 ^ (*r1 & t0)
	*r2 = t2 ^ (*r2 | t3)
	t4 := *r3 & (t1 ^ t3)
	*r1 = (^t1) ^ t4
	*r0 = t4 ^ (^t3)
}

// Inverse S-Box 0
func sb0Inv(r0, r1, r2, r3 *uint32) {
	t0 := ^(*r0)
	t1 := *r0 ^ *r1
	t2 := *r3 ^ (t0 | t1)
	t3 := *r2 ^ t2
	*r2 = t1 ^ t3
	t4 := t0 ^ (*r3 & t1)
	*r1 = t2 ^ (*r2 & t4)
	*r3 = (*r0 & t2) ^ (t3 | *r1)
	*r0 = *r3 ^ (t3 ^ t4)
}

// S-Box 1
func sb1(r0, r1, r2, r3 *uint32) {
	t0 := *r1 ^ (^(*r0))
	t1 := *r2 ^ (*r0 | t0)
	*r2 = *r3 ^ t1
	t2 := *r1 ^ (*r3 | t0)
	t3 := t0 ^ *r2
	*r3 = t3 ^ (t1 & t2)
	t4 := t1 ^ t2
	*r1 = *r3 ^ t4
	*r0 = t1 ^ (t3 & t4)
}

// Inverse S-Box 1
func sb1Inv(r0, r1, r2, r3 *uint32) {
	t0 := *r1 ^ *r3
	t1 := *r0 ^ (*r1 & t0)
	t2 := t0 ^ t1
	*r3 = *r2 ^ t2
	t3 := *r1 ^ (t0 & t1)
	t4 := *r3 | t3
	*r1 = t1 ^ t4
	t5 := ^(*r1)
	t6 := *r3 ^ t3
	*r0 = t5 ^ t6
	*r2 = t2 ^ (t5 | t6)
}

// S-Box 2
func sb2(r0, r1, r2, r3 *uint32) {
	v0 := *r0 // save r0
	v3 := *r3 // save r3
	t0 := ^v0
	t1 := *r1 ^ v3
	t2 := *r2 & t0
	*r0 = t1 ^ t2
	t3 := *r2 ^ t0
	t4 := *r2 ^ *r0
	t5 := *r1 & t4
	*r3 = t3 ^ t5
	*r2 = v0 ^ ((v3 | t5) & (*r0 | t3))
	*r1 = (t1 ^ *r3) ^ (*r2 ^ (v3 | t0))
}

// Inverse S-Box 2
func sb2Inv(r0, r1, r2, r3 *uint32) {
	v0 := *r0 // save r0
	v3 := *r3 // save r3
	t0 := *r1 ^ v3
	t1 := ^t0
	t2 := v0 ^ *r2
	t3 := *r2 ^ t0
	t4 := *r1 & t3
	*r0 = t2 ^ t4
	t5 := v0 | t1
	t6 := v3 ^ t5
	t7 := t2 | t6
	*r3 = t0 ^ t7
	t8 := ^t3
	t9 := *r0 | *r3
	*r1 = t8 ^ t9
	*r2 = (v3 & t8) ^ (t2 ^ t9)
}

// S-Box 3
func sb3(r0, r1, r2, r3 *uint32) {
	v1 := *r1 // save r1
	v3 := *r3 // save r3
	t0 := *r0 ^ *r1
	t1 := *r0 & *r2
	t2 := *r0 | *r3
	t3 := *r2 ^ *r3
	t4 := t0 & t2
	t5 := t1 | t4
	*r2 = t3 ^ t5
	t6 := *r1 ^ t2
	t7 := t5 ^ t6
	t8 := t3 & t7
	*r0 = t0 ^ t8
	t9 := *r2 & *r0
	*r1 = t7 ^ t9
	*r3 = (v1 | v3) ^ (t3 ^ t9)
}

// Inverse S-Box 3
func sb3Inv(r0, r1, r2, r3 *uint32) {
	t0 := *r0 | *r1
	t1 := *r1 ^ *r2
	t2 := *r1 & t1
	t3 := *r0 ^ t2
	t4 := *r2 ^ t3
	t5 := *r3 | t3
	*r0 = t1 ^ t5
	t6 := t1 | t5
	t7 := *r3 ^ t6
	*r2 = t4 ^ t7
	t8 := t0 ^ t7
	t9 := *r0 & t8
	*r3 = t3 ^ t9
	*r1 = *r3 ^ (*r0 ^ t8)
}

// S-Box 4
func sb4(r0, r1, r2, r3 *uint32) {
	v0 := *r0 // save r0
	t0 := v0 ^ *r3
	t1 := *r3 & t0
	t2 := *r2 ^ t1
	t3 := *r1 | t2
	*r3 = t0 ^ t3
	t4 := ^(*r1)
	t5 := t0 | t4
	*r0 = t2 ^ t5
	t6 := v0 & *r0
	t7 := t0 ^ t4
	t8 := t3 & t7
	*r2 = t6 ^ t8
	*r1 = (v0 ^ t2) ^ (t7 & *r2)
}

// Inverse S-Box 4
func sb4Inv(r0, r1, r2, r3 *uint32) {
	v3 := *r3 // save r3
	t0 := *r2 | v3
	t1 := *r0 & t0
	t2 := *r1 ^ t1
	t3 := *r0 & t2
	t4 := *r2 ^ t3
	*r1 = v3 ^ t4
	t5 := ^(*r0)
	t6 := t4 & *r1
	*r3 = t2 ^ t6
	t7 := *r1 | t5
	t8 := v3 ^ t7
	*r0 = *r3 ^ t8
	*r2 = (t2 & t8) ^ (*r1 ^ t5)
}

// S-Box 5
func sb5(r0, r1, r2, r3 *uint32) {
	v1 := *r1 // save r1
	t0 := ^(*r0)
	t1 := *r0 ^ v1
	t2 := *r0 ^ *r3
	t3 := *r2 ^ t0
	t4 := t1 | t2
	*r0 = t3 ^ t4
	t5 := *r3 & *r0
	t6 := t1 ^ *r0
	*r1 = t5 ^ t6
	t7 := t0 | *r0
	t8 := t1 | t5
	t9 := t2 ^ t7
	*r2 = t8 ^ t9
	*r3 = (v1 ^ t5) ^ (*r1 & t9)
}

// Inverse S-Box 5
func sb5Inv(r0, r1, r2, r3 *uint32) {
	v0 := *r0 // save r0
	v1 := *r1 // save r1
	v3 := *r3 // save r3
	t0 := ^(*r2)
	t1 := v1 & t0
	t2 := v3 ^ t1
	t3 := v0 & t2
	t4 := v1 ^ t0
	*r3 = t3 ^ t4
	t5 := v1 | *r3
	t6 := v0 & t5
	*r1 = t2 ^ t6
	t7 := v0 | v3
	t8 := t0 ^ t5
	*r0 = t7 ^ t8
	*r2 = (v1 & t7) ^ (t3 | (v0 ^ *r2))
}

// S-Box 6
func sb6(r0, r1, r2, r3 *uint32) {
	t0 := ^(*r0)
	t1 := *r0 ^ *r3
	t2 := *r1 ^ t1
	t3 := t0 | t1
	t4 := *r2 ^ t3
	*r1 = *r1 ^ t4
	t5 := t1 | *r1
	t6 := *r3 ^ t5
	t7 := t4 & t6
	*r2 = t2 ^ t7
	t8 := t4 ^ t6
	*r0 = *r2 ^ t8
	*r3 = (^t4) ^ (t2 & t8)
}

// Inverse S-Box 6
func sb6Inv(r0, r1, r2, r3 *uint32) {
	v1 := *r1 // save r1
	v3 := *r3 // save r3
	t0 := ^(*r0)
	t1 := *r0 ^ v1
	t2 := *r2 ^ t1
	t3 := *r2 | t0
	t4 := v3 ^ t3
	*r1 = t2 ^ t4
	t5 := t2 & t4
	t6 := t1 ^ t5
	t7 := v1 | t6
	*r3 = t4 ^ t7
	t8 := v1 | *r3
	*r0 = t6 ^ t8
	*r2 = (v3 & t0) ^ (t2 ^ t8)
}

// S-Box 7
func sb7(r0, r1, r2, r3 *uint32) {
	t0 := *r1 ^ *r2
	t1 := *r2 & t0
	t2 := *r3 ^ t1
	t3 := *r0 ^ t2
	t4 := *r3 | t0
	t5 := t3 & t4
	*r1 = *r1 ^ t5
	t6 := t2 | *r1
	t7 := *r0 & t3
	*r3 = t0 ^ t7
	t8 := t3 ^ t6
	t9 := *r3 & t8
	*r2 = t2 ^ t9
	*r0 = (^t8) ^ (*r3 & *r2)
}

// Inverse S-Box 7
func sb7Inv(r0, r1, r2, r3 *uint32) {
	v0 := *r0 // save r0
	v3 := *r3 // save r3
	t0 := *r2 | (v0 & *r1)
	t1 := v3 & (v0 | *r1)
	*r3 = t0 ^ t1
	t2 := ^v3
	t3 := *r1 ^ t1
	t4 := t3 | (*r3 ^ t2)
	*r1 = v0 ^ t4
	*r0 = (*r2 ^ t3) ^ (v3 | *r1)
	*r2 = (t0 ^ *r1) ^ (*r0 ^ (v0 & *r3))
}
