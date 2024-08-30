package cjwt

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// Claims — структура утверждений, которая включает стандартные утверждения и
// одно пользовательское UserID
type Claims struct {
	jwt.RegisteredClaims
	UserID int
}

const tokenExp = time.Hour * 24 * 7
const secretKey = "superPuperSecretKey"

// BuildJWTString создаёт токен и возвращает его в виде строки.
func BuildJWTString(userID int) (string, error) {
	// создаём новый токен с алгоритмом подписи HS256 и утверждениями — Claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			// когда создан токен
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenExp)),
		},
		// собственное утверждение
		UserID: userID,
	})

	// создаём строку токена
	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}

	// возвращаем строку токена
	return tokenString, nil
}

// GetUserID - получает UserID из токена.
func GetUserID(tokenString string) int {
	if len(tokenString) == 0 {
		return -1
	}
	// создаём экземпляр структуры с утверждениями
	claims := &Claims{}
	// парсим из строки токена tokenString в структуру claims
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secretKey), nil
	})

	if err != nil {
		return -1
	}

	if !token.Valid {
		return -1
	}

	// возвращаем ID пользователя в читаемом виде
	return claims.UserID
}

type UserNum string

func JWTInterceptor(
	ctx context.Context,
	req interface{},
	i *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	isRegisterUserMethod := strings.Contains(i.FullMethod, "RegisterUser")
	isAuthUserMethod := strings.Contains(i.FullMethod, "AuthUser")
	isCheckServiceMethod := strings.Contains(i.FullMethod, "CheckService")

	if isRegisterUserMethod || isAuthUserMethod || isCheckServiceMethod {
		return handler(ctx, req)
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New(`broken context metadata`)
	}

	reqToken := ``
	bearerTokens := md[`authorization`]
	if len(bearerTokens) > 0 {
		splitToken := strings.Split(bearerTokens[0], "Bearer ")
		reqToken = splitToken[1]
	}

	userNumber := UserNum(`UserID`)
	UserID := GetUserID(reqToken)

	newCtx := context.WithValue(ctx, userNumber, strconv.Itoa(UserID))
	return handler(newCtx, req)
}
