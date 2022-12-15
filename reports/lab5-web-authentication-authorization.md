# Topic: Web Authentication & Authorisation

## Course: Cryptography & Security

### Author: Viorel Noroc

----

## Theory

&ensp;&ensp;&ensp; Authentication & authorization are 2 of the main security goals of IT systems and should not be used interchangibly. Simply put, during authentication the system verifies the identity of a user or service, and during authorization the system checks the access rights, optionally based on a given user role.

&ensp;&ensp;&ensp; There are multiple types of authentication based on the implementation mechanism or the data provided by the user. Some usual ones would be the following:

- Based on credentials (Username/Password);
- Multi-Factor Authentication (2FA, MFA);
- Based on digital certificates;
- Based on biometrics;
- Based on tokens.

&ensp;&ensp;&ensp; Regarding authorization, the most popular mechanisms are the following:

- Role Based Access Control (RBAC): Base on the role of a user;
- Attribute Based Access Control (ABAC): Based on a characteristic/attribute of a user.
[[1]](https://github.com/DrVasile/CS-Labs/blob/master/LaboratoryWork5/laboratoryWork5Task.md)

## Objectives

1. Take what you have at the moment from previous laboratory works and put it in a web service / serveral web services.
2. Your services should have implemented basic authentication and MFA (the authentication factors of your choice).
3. Your web app needs to simulate user authorization and the way you authorise user is also a choice that needs to be done by you.
4. As services that your application could provide, you could use the classical ciphers. Basically the user would like to get access and use the classical ciphers, but they need to authenticate and be authorized.

## Implementation description

### Web service

The web service is implemented using gin package.

```go
    ginEngine := gin.Default()
    apiRoutes := ginEngine.Group("/api")
```

For basic authentication there are the endpoints `api/user/register` and `api/use/login`.

For the registration endpoint, the user email and password are deserialized, the otp is verified then it is registered using an userService similar to the previous laboratory work user service.

```go
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
```

```go
func (s *OtpService) Verify(email string, otp string) error {
    if s.otpMap[email] != otp {
        return errors.New("OtpService Verify | OTP is not valid")
    }

    delete(s.otpMap, email)

    return nil
}
```

The login is almost the same but at the end a JWT token with expiration of 1 hour is generated and sent back.

```go
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
```

```go
func (s *UserService) Login(dto dto.UserDto) (string, error) {
    user, err := s.Get(dto.Email)
    if err != nil {
        return "", err
    }

    hashedPassword := utils.GetSHA256Digest(dto.Password)

    if !bytes.Equal(hashedPassword, user.Password) {
        return "", errors.New("UserService Login | Invalid password")
    }

    jwt, err := jwt.Generate(user.Email, user.Role)
    if err != nil {
        return "", err
    }

    return jwt, nil
}
```

```go
func Generate(email, role string) (string, error) {

    secret := os.Getenv("SECRET")

    claims := jwt.MapClaims{}
    claims["authorized"] = true
    claims["email"] = email
    claims["role"] = role
    claims["exp"] = time.Now().Add(1 * time.Hour).Unix()
    jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

    signedToken, err := jwtToken.SignedString([]byte(secret))
    if err != nil {
        return "", err
    }

    return signedToken, nil
}
```

### MFA

For multi factor authentication, a simple one time password is sent to the user's email address. The user should access the endpoint with his email to receive an OTP.

```go
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
```

The OTP is just a number from 100000 to 999999 like in many other web services

```go
func (s *OtpService) Generate(email string) (string, error) {
    otpNum := 100000 + rand.Intn(899999)
    otp := strconv.Itoa(otpNum)

    s.otpMap[email] = otp

    return otp, nil
}
```

### Authentication

To verify if the user is authenticated, a middleware that checks the user's JWT token is used. It extracts the email and role of the user from the existing token in the context. If in the current context has no token, it tries to extract the token from from HTTP Authorization header. If nothing was found, obviously the token is invalid.

```go
func JwtAuth() gin.HandlerFunc {
    return func(c *gin.Context) {
        email, role, err := jwt.ExtractEmailAndRole(c)
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
            c.Abort()
            return
        }
        c.Set("email", email)
        c.Set("role", role)
        c.Next()
    }
}
```

```go
unc ExtractEmailAndRole(c *gin.Context) (string, string, error) {

    secret := os.Getenv("SECRET")

    authToken := c.Query("token")
    if authToken == "" {

        bearerToken := c.Request.Header.Get("Authorization")

        if len(strings.Split(bearerToken, " ")) == 2 {
            authToken = strings.Split(bearerToken, " ")[1]
        }
    }

    jwtToken, err := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return []byte(secret), nil
    })
    if err != nil {
        return "", "", err
    }

    claims, ok := jwtToken.Claims.(jwt.MapClaims)
    if ok && jwtToken.Valid {
        email := claims["email"].(string)
        role := claims["role"].(string)
        return email, role, nil
    }

    return "", "", nil
}

```

Authenticated users can use some ciphers from the previous labs

```go
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
```

### Authorization

The authorization is based on the used roles. A middleware is used to check for the user role on the needed endpoints.

```go
func WithRole(role string) gin.HandlerFunc {
    return func(c *gin.Context) {
        roleFromToken := c.GetString("role")
        if roleFromToken != role {
            c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
            c.Abort()
            return
        }
        c.Next()
    }
}
```

Only admin users can get a list of all users or get an user based on the email.

```go
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
```

### Conclusion

In this laboratory work it was implemented a REST API that registers users only with an one time password, handles authentication with JWT tokens and authorization based on roles. Only authenticated users can use the other endpoints that encrypt and decrypt messages with some classical ciphers. Only admin users can get a list of all users or a user based on the email.

This laboratory work was an interesting one, but I didn't learn much from it because we already used this on another course where we need to implement a secure application.
