package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"na3/na3-auth/config"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	initdata "github.com/telegram-mini-apps/init-data-golang"
)

type AuthController struct {
}

func ValidateInitData(initData string, hostname string) (initdata.InitData, error) {
	config := config.GetConfig()
	fmt.Println("Hostname:", hostname)
	if hostname == "" {
		hostname = "default"
	}

	token := config.GetString("telegram." + hostname + ".token")
	expIn := config.GetDuration("telegram." + hostname + ".expiration")

	if token == "" {
		token = config.GetString("telegram.default.token")
		expIn = config.GetDuration("telegram.default.expiration")
	}
	fmt.Println("Token: ", token)

	err := initdata.Validate(initData, token, expIn)

	if err != nil {
		return initdata.InitData{}, err
	}

	data, err := initdata.Parse(initData)

	return data, err
}

type JWTClaims struct {
	ID         int    `json:"id" binding:"required"`
	TelegramID int    `json:"telegram_id" binding:"required"`
	Username   string `json:"username"`
	IsPremium  bool   `json:"is_premium"`
}

func SignJWT(jwtClaims JWTClaims) (string, error) {
	config := config.GetConfig()
	secretKey := config.GetString("jwt.secret")
	expIn := config.GetDuration("jwt.expiration")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":          jwtClaims.ID,
		"telegram_id": jwtClaims.TelegramID,
		"username":    jwtClaims.Username,
		"is_premium":  jwtClaims.IsPremium,
		"exp":         time.Now().Add(expIn).Unix(), // Token expiration time
	})
	tokenString, err := token.SignedString([]byte(secretKey))

	return tokenString, err
}

func ValidateJWT(jwtToken string) (JWTClaims, error) {
	claims := JWTClaims{}
	config := config.GetConfig()
	secretKey := config.GetString("jwt.secret")

	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil {
		return claims, err
	}

	if token.Valid {
		claimsMap := token.Claims.(jwt.MapClaims)
		claims.ID = int(claimsMap["id"].(float64))
		claims.TelegramID = int(claimsMap["telegram_id"].(float64))
		claims.Username = claimsMap["username"].(string)
		claims.IsPremium = claimsMap["is_premium"].(bool)
	}

	return claims, nil
}

func (u AuthController) Auth(c *gin.Context) {
	uri := c.Request.Header.Get("X-Forwarded-Uri")
	token := ""
	authorization := c.Request.Header.Get("Authorization")

	if authorization != "" {
		res := strings.Split(authorization, " ")
		if len(res) == 2 {
			authType := res[0]
			token = res[1]

			if authType != "Bearer" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized", "status": http.StatusUnauthorized})
				return
			}
		}
	} else if uri != "" {
		u, err := url.Parse(uri)
		if err == nil {
			q, err := url.ParseQuery(u.RawQuery)
			if err == nil && q.Get("token") != "" {
				token = q.Get("token")
			}
		}
	}

	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized", "status": http.StatusUnauthorized})
		return
	}

	data, err := ValidateJWT(token)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized", "status": http.StatusUnauthorized})
		return
	}
	bytes, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}

	c.Header("X-Auth-User", string(bytes))
	c.JSON(http.StatusOK, gin.H{"message": "Authorized", "status": http.StatusOK})
}

func (u AuthController) AddHeaderAuth(c *gin.Context) {
	uri := c.Request.Header.Get("X-Forwarded-Uri")
	authorization := c.Request.Header.Get("Authorization")
	token := ""

	if authorization != "" {
		res := strings.Split(authorization, " ")
		if len(res) == 2 {
			authType := res[0]
			token = res[1]

			if authType != "Bearer" {
				c.JSON(http.StatusUnauthorized, gin.H{"status": http.StatusUnauthorized})
				return
			}
		}
	} else if uri != "" {
		u, err := url.Parse(uri)
		if err == nil {
			q, err := url.ParseQuery(u.RawQuery)
			if err == nil && q.Get("token") != "" {
				token = q.Get("token")
			}
		}
	}

	if token != "" {
		data, err := ValidateJWT(token)

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"status": http.StatusUnauthorized})
			return
		}
		bytes, err := json.Marshal(data)

		if err != nil {
			panic(err)
		}

		c.Header("X-Auth-User", string(bytes))
	}

	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK})
}

type ValidateBody struct {
	InitData string `json:"initData" binding:"required"`
	Hostname string `json:"hostname"`
}

func (u AuthController) ValidateTelegramToken(c *gin.Context) {
	body := ValidateBody{}
	if err := c.BindJSON(&body); err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	data, err := ValidateInitData(body.InitData, body.Hostname)

	if err != nil || data.Receiver.IsBot {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized", "status": http.StatusUnauthorized})
		return
	}

	c.JSON(http.StatusOK, data.User)
}

func (u AuthController) SignToken(c *gin.Context) {
	body := JWTClaims{}
	if err := c.BindJSON(&body); err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	token, err := SignJWT(body)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}
