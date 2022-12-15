# Laboratory works for Cryptography and Security course

## Run app

Create .env file on the same scope as main.go with the following structure:

```text
SECRET = secret for signing jwt token
EMAIL = send otp from this email
EMAIL_PASSWORD = above email password
SMTP_HOST = the smpt host of your email provider
SMTP_PORT = port for the host above
```

Run command
```powershell
go run .
```

## Run ciphers tests

```console-commands
go test ./classic-ciphers/tests
go test ./stream-block-ciphers/tests
go test ./asymmetric-ciphers/tests
go test ./hash-func-and-digital-sign/tests
```
