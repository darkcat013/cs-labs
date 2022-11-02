package interfaces

type Cipher interface {
	EncryptMessage(s string) string
	DecryptMessage(s string) string
}
