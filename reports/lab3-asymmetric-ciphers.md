# Asymmetric Ciphers

## Course: Cryptography & Security

## Author: Viorel Noroc

----

## Theory

&ensp;&ensp;&ensp; Asymmetric Cryptography (a.k.a. Public-Key Cryptography)deals with the encryption of plain text when having 2 keys, one being public and the other one private. The keys form a pair and despite being different they are related.

&ensp;&ensp;&ensp; As the name implies, the public key is available to the public but the private one is available only to the authenticated recipients

&ensp;&ensp;&ensp; A popular use case of the asymmetric encryption is in SSL/TLS certificates along side symmetric encryption mechanisms. It is necessary to use both types of encryption because asymmetric ciphers are computationally expensive, so these are usually used for the communication initiation and key exchange, or sometimes called handshake. The messages after that are encrypted with symmetric ciphers.[[1]](https://github.com/DrVasile/CS-Labs/blob/master/LaboratoryWork3/laboratoryWork3Task.md)

### Examples

1. RSA
2. Diffie-Helman
3. ECC
4. El Gamal
5. DSA

## Objectives

1. Get familiar with the asymmetric cryptography mechanisms.

2. Implement an example of an asymmetric cipher (RSA).

## Implementation description

### RSA

RSA is an asymmetric cipher that uses the fact that it is easy to find the prime factors of a large number, but it is difficult to find the prime factors of a product of two large prime numbers. It uses two keys, one public and one private. The public key is used to encrypt the message and the private key is used to decrypt the message.

**Keys generation steps:**

1. Generate two large prime numbers `p` and `q`.

    ```go
        p, err := rand.Prime(reader, bits/2)
        if err != nil {
            return RSA{}, err
        }

        q, err := rand.Prime(reader, bits/2)
        if err != nil {
            return RSA{}, err
        }
    ```

2. Compute `n = p * q`.

    ```go
        n := new(big.Int).Mul(p, q)
    ```

3. Compute `phi(n) = (p - 1) * (q - 1)`.

    ```go
        phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
    ```

4. Choose an integer `e` such that `1 < e < phi(n)` and `gcd(e, phi(n)) = 1`. This is the public key.

    ```go
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
    ```

5. Compute `d` such that `d * e = 1 mod phi(n)`. This is the private key.

    ```go
        d := new(big.Int).ModInverse(e, phi)
    ```

### Encryption

To compute cypher text `enc` from plain text `m` we use the following formula: `c = m^e mod n`.

```go
    enc := new(big.Int).Exp(m, r.E, r.N)
```

### Decryption

To compute plain text `dec` from cypher text `c` we use the following formula: `m = c^d mod n`.

```go
    dec := new(big.Int).Exp(c, r.D, r.N)
```

## Conclusions

This laboratory work was an useful one for me because it taught me how asymmetric ciphers work and where they are mainly used. I chose to implement RSA because it is fairly easy to understand and it is very popular, despite being quite old. Its disantvatage however is that it can be slow when used on large amount of data but nonetheless it is very secure.

Exapmple output from `main.go`

Private key:  14716287574320593947 15361576906565017907

Public key:  5451654952410231763 15361576906565017907

Message: hello

Encrypted: �♀�����.

Decrypted: hello

## References

[1] <https://github.com/DrVasile/CS-Labs/blob/master/LaboratoryWork3/laboratoryWork3Task.md>