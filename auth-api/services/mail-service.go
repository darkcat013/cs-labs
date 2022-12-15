package services

import (
	"fmt"
	"net/smtp"
	"os"
	"strings"

	"github.com/darkcat013/cs-labs/auth-api/domain"
)

type MailService struct {
	from string
	addr string
	auth smtp.Auth
}

func NewMailService() *MailService {

	email := os.Getenv("EMAIL")
	password := os.Getenv("EMAIL_PASSWORD")
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	addr := smtpHost + ":" + smtpPort
	auth := smtp.PlainAuth("", email, password, smtpHost)

	mailService := &MailService{
		from: email,
		addr: addr,
		auth: auth,
	}

	return mailService
}

func (s *MailService) Send(mail domain.Mail) {
	from := "Cryptography laboratory"

	mailText := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\r\n"
	mailText += fmt.Sprintf("From: %s\r\n", from)
	mailText += fmt.Sprintf("To: %s\r\n", strings.Join(mail.To, ";"))
	mailText += fmt.Sprintf("Subject: %s\r\n", mail.Subject)
	mailText += fmt.Sprintf("\r\n%s\r\n", mail.Body)

	smtp.SendMail(s.addr, s.auth, s.from, mail.To, []byte(mailText))
}
