package authapi

import (
	"fmt"

	"github.com/darkcat013/cs-labs/auth-api/constants"
	"github.com/darkcat013/cs-labs/auth-api/domain"
	"github.com/darkcat013/cs-labs/auth-api/dto"
	"github.com/darkcat013/cs-labs/auth-api/middleware"
	"github.com/darkcat013/cs-labs/auth-api/services"
	ciphers "github.com/darkcat013/cs-labs/classic-ciphers"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func StartServer() error {
	godotenv.Load()

	userService := services.NewUserService()
	otpService := services.NewOtpService()
	mailService := services.NewMailService()

	ginEngine := gin.Default()
	apiRoutes := ginEngine.Group("/api")

	apiRoutes.POST("/user/register", func(c *gin.Context) {
		var userDto dto.UserDto

		if err := c.ShouldBindJSON(&userDto); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		if err := otpService.Verify(userDto.Email, userDto.Otp); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		if err := userService.Register(userDto); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		c.JSON(201, nil)
	})

	apiRoutes.POST("/user/login", func(c *gin.Context) {
		var userDto dto.UserDto

		if err := c.ShouldBindJSON(&userDto); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		if err := otpService.Verify(userDto.Email, userDto.Otp); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		jwt, err := userService.Login(userDto)
		if err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		c.JSON(200, gin.H{"token": jwt})
	})

	apiRoutes.POST("/otp/:email", func(c *gin.Context) {
		email := c.Param("email")

		otp, err := otpService.Generate(email)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		mail := domain.Mail{
			To:      []string{email},
			Subject: "Cryptography Lab OTP",
			Body:    fmt.Sprintf("Your OTP is %s", otp),
		}

		go mailService.Send(mail)

		c.JSON(200, gin.H{"message": "OTP sent to your email."})
	})

	authenticatedRoutes := apiRoutes.Use(middleware.JwtAuth())

	authenticatedRoutes.POST("/caesar/encrypt", func(c *gin.Context) {
		var caesarDto dto.CaesarDto

		if err := c.ShouldBindJSON(&caesarDto); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		caesar := ciphers.Caesar{
			Key: caesarDto.Key,
		}

		cipherText := caesar.EncryptMessage(caesarDto.Text)

		caesarDto.Text = cipherText

		c.JSON(200, caesarDto)
	})

	authenticatedRoutes.POST("/caesar/decrypt", func(c *gin.Context) {
		var caesarDto dto.CaesarDto

		if err := c.ShouldBindJSON(&caesarDto); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		caesar := ciphers.Caesar{
			Key: caesarDto.Key,
		}

		plainText := caesar.DecryptMessage(caesarDto.Text)

		caesarDto.Text = plainText

		c.JSON(200, caesarDto)
	})

	authenticatedRoutes.POST("/polybius/decrypt", func(c *gin.Context) {
		var polybiusDto dto.PolybiusDto

		if err := c.ShouldBindJSON(&polybiusDto); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		polybius := ciphers.PolybiusEnglish{
			ColumnKey: polybiusDto.ColumnKey,
			RowKey:    polybiusDto.RowKey,
		}

		plainText := polybius.DecryptMessage(polybiusDto.Text)

		polybiusDto.Text = plainText

		c.JSON(200, polybiusDto)
	})

	authenticatedRoutes.POST("/polybius/encrypt", func(c *gin.Context) {
		var polybiusDto dto.PolybiusDto

		if err := c.ShouldBindJSON(&polybiusDto); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		polybius := ciphers.PolybiusEnglish{
			ColumnKey: polybiusDto.ColumnKey,
			RowKey:    polybiusDto.RowKey,
		}

		cipherText := polybius.EncryptMessage(polybiusDto.Text)

		polybiusDto.Text = cipherText

		c.JSON(200, polybiusDto)
	})

	adminRoutes := authenticatedRoutes.Use(middleware.WithRole(constants.ROLE_ADMIN))

	adminRoutes.GET("/admin/users", func(c *gin.Context) {
		users, err := userService.GetAll()
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		c.JSON(200, users)
	})

	adminRoutes.GET("/admin/users/:email", func(c *gin.Context) {
		email := c.Param("email")

		user, err := userService.Get(email)
		if err != nil {
			c.JSON(404, gin.H{"error": err.Error()})
			return
		}

		c.JSON(200, user)
	})

	return ginEngine.Run(":8080")
}
