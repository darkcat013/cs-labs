package services

import (
	"errors"
	"math/rand"
	"strconv"
)

type OtpService struct {
	otpMap map[string]string
}

func NewOtpService() *OtpService {

	return &OtpService{
		otpMap: make(map[string]string),
	}
}

func (s *OtpService) Generate(email string) (string, error) {
	otpNum := 100000 + rand.Intn(899999)
	otp := strconv.Itoa(otpNum)

	s.otpMap[email] = otp

	return otp, nil
}

func (s *OtpService) Verify(email string, otp string) error {
	if s.otpMap[email] != otp {
		return errors.New("OtpService Verify | OTP is not valid")
	}

	delete(s.otpMap, email)

	return nil
}
