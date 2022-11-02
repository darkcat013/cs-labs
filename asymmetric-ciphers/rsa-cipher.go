package ciphers

import (
	"crypto/rand"
	"io"
	"math/big"
)

type RSA struct {
	N *big.Int // modulus
	E *big.Int // public exponent
	D *big.Int // private exponent
}

// GenerateKey generates an RSA keypair of the given bit size using the
// random source rand (for example, crypto/rand.Reader).
func GenerateRSAKeys(reader io.Reader, bits int) (rsa RSA, err error) {
	p, err := rand.Prime(reader, bits/2)
	if err != nil {
		return RSA{}, err
	}

	q, err := rand.Prime(reader, bits/2)
	if err != nil {
		return RSA{}, err
	}

	// n = p * q
	n := new(big.Int).Mul(p, q)

	// phi = (p-1) * (q-1)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))

	// 1 < e < phi, gcd(e,phi) = 1
	e, err := rand.Int(rand.Reader, phi)
	if err != nil {
		return RSA{}, err
	}
	gcd := big.Int{}
	for gcd.GCD(nil, nil, e, phi).Cmp(big.NewInt(1)) != 0 {
		e, err = rand.Int(rand.Reader, phi)
		if err != nil {
			return RSA{}, err
		}
	}

	// d = e^-1 mod phi
	d := new(big.Int).ModInverse(e, phi)

	r := RSA{
		N: n,
		E: e,
		D: d,
	}

	return r, err
}

func (r RSA) EncryptMessage(s string) string {
	m := new(big.Int).SetBytes([]byte(s))
	// enc = m^e mod n
	enc := new(big.Int).Exp(m, r.E, r.N)
	return string(enc.Bytes())
}

func (r RSA) DecryptMessage(s string) string {
	c := new(big.Int).SetBytes([]byte(s))
	// dec = c^d mod n
	dec := new(big.Int).Exp(c, r.D, r.N)
	return string(dec.Bytes())
}
