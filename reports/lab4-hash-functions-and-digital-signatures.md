# Hash functions and Digital Signatures

## Course: Cryptography & Security

### Author: Viorel Noroc

----

## Theory

&ensp;&ensp;&ensp; Hashing is a technique used to compute a new representation of an existing value, message or any piece of text. The new representation is also commonly called a digest of the initial text, and it is a one way function meaning that it should be impossible to retrieve the initial content from the digest.

&ensp;&ensp;&ensp; Such a technique has the following usages:

* Offering confidentiality when storing passwords,
* Checking for integrity for some downloaded files or content,
* Creation of digital signatures, which provides integrity and non-repudiation.

&ensp;&ensp;&ensp; In order to create digital signatures, the initial message or text needs to be hashed to get the digest. After that, the digest is to be encrypted using a public key encryption cipher. Having this, the obtained digital signature can be decrypted with the public key and the hash can be compared with an additional hash computed from the received message to check the integrity of it.[[1]](https://github.com/DrVasile/CS-Labs/blob/master/LaboratoryWork4/laboratoryWork4Task.md)

### Examples

1. Argon2
2. BCrypt
3. MD5 (Deprecated due to collisions)
4. RipeMD
5. SHA256 (And other variations of SHA)
6. Whirlpool

## Objectives

1. Get familiar with the hashing techniques/algorithms.
2. Use an appropriate hashing algorithms to store passwords in a local DB.
    1. You can use already implemented algortihms from libraries provided for your language.
    2. The DB choise is up to you, but it can be something simple, like an in memory one.
3. Use an asymmetric cipher to implement a digital signature process for a user message.
    1. Take the user input message.
    2. Preprocess the message, if needed.
    3. Get a digest of it via hashing.
    4. Encrypt it with the chosen cipher.
    5. Perform a digital signature check by comparing the hash of the message with the decrypted one.

## Implementation description

### Storing and checking user passwords

This laboratory implementation uses a map of users as some kind of in-memory database. This database implements the IDatabase interface.

```go
type User struct {
    Username string
    Password []byte
    Key      *rsa.PrivateKey
}

type InMemoryDatabase struct {
    Users map[string]domain.User
}

type IDatabase interface {
    Get(id string) (domain.User, error)
    Set(id string, value domain.User) error
    Delete(id string) error
}
```

To register users and authenticate them, an User Service was implemented which hashes passwords using the SHA256 algorithm and generates an RSA pair of keys for each user.

```go
type IUserService interface {
    Register(username, password string) error
    Login(username, password string) (domain.User, error)
}

type UserService struct {
    Users interfaces.IDatabase
}

func (s *UserService) Register(username, password string) error {

    _, err := s.Users.Get(username)
    if err == nil {
        return errors.New("UserService Register | User already exists")
    }

    hashedPassword := utils.GetSHA256Digest(password)

    key, err := rsa.GenerateKey(rand.Reader, 1028)
    if err != nil {
        return err
    }

    user := domain.User{
        Username: username,
        Password: hashedPassword,
        Key:      key,
    }

    return s.Users.Set(username, user)
}

func (s *UserService) Login(username, password string) (domain.User, error) {
    user, err := s.Users.Get(username)
    if err != nil {
        return domain.User{}, err
    }

    hashedPassword := utils.GetSHA256Digest(password)

    if !bytes.Equal(hashedPassword, user.Password) {
        return domain.User{}, errors.New("UserService Login | Invalid password")
    }

    return user, nil
}

func GetSHA256Digest(input string) []byte {
    hash := sha256.New()
    _, err := hash.Write([]byte(input))
    if err != nil {
        panic(err)
    }
    return hash.Sum(nil)
}
```

### Creating and checking messages

To create and check messages using a digital signature, a Message Service was implemented which uses the RSA algorithm to create and check digital signatures.

```go
type IMessageService interface {
    NewMessage(from domain.User, message string) (hashedMessage []byte, signature []byte, err error)
    CheckMessage(publicKey *rsa.PublicKey, hashedMessage, signature []byte) error
}

type MessageService struct{}

func (s *MessageService) NewMessage(from domain.User, message string) (hashedMessage []byte, signature []byte, err error) {
    hashedMessage = utils.GetSHA256Digest(message)

    signature, err = rsa.SignPKCS1v15(rand.Reader, from.Key, crypto.SHA256, hashedMessage)

    if err != nil {
        return nil, nil, errors.New("MessageService | Could not create new message")
    }

    return hashedMessage, signature, nil
}

func (s *MessageService) CheckMessage(publicKey *rsa.PublicKey, hashedMessage, signature []byte) error {
    err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, []byte(hashedMessage), []byte(signature))
    if err != nil {
        return errors.New("MessageService | Message signature check failed")
    }
    return nil
}
```

## Conclusions

This laboratory work was an interesting and useful one, thanks to it I learned more about hash functions and digital signatures by using the already existing libraries for SHA256 and RSA of Go programming language. Hashing algorithms are fast and are usually used to check for integrity of large files, store passwords and create digital signaturees. Following from this, digital signatures are used to verify the authenticity of almost anything that an user can send over a network.
