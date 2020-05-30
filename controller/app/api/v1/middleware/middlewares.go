package middleware

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"

	"hyperline-controller/app/lib/common"
	sess "hyperline-controller/app/lib/session"
	"hyperline-controller/app/model"
	"hyperline-controller/env"
)

type (
	JSON = map[string]interface{}
	User = model.User
)

var (
	secretKey   []byte
	sessManager = sess.SessManager
)

func init() {
	key, err := ioutil.ReadFile(env.JWTSecret)
	if err != nil {
		log.Fatal("Failed to load JWT Secret key from " + env.JWTSecret)
	}

	secretKey = key
}

func getTokenData(tokenStr string) (JSON, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("Unexpected token signing method")
		}

		return secretKey, nil
	})

	if err != nil {
		return JSON{}, err
	}

	if !token.Valid {
		return JSON{}, errors.New("Invalid token")
	}

	return token.Claims.(jwt.MapClaims), nil
}

func ValidateSessionID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("In validateToken Middleware")
		sessId, err := sessManager.GetSessionId(r)
		if err != nil {
			log.Println("token : " + err.Error())
			next.ServeHTTP(w, r)
			return
		}

		data, err := getTokenData(sessId)
		if err != nil {
			log.Println("data : " + err.Error())
			next.ServeHTTP(w, r)
			return
		}

		var user User
		user.Load(data["user"].(JSON))

		sess, err := sessManager.SessionReadOrCreate(r)
		if err != nil {
			log.Println("[ValidateSessionID] ::: Failed to get session : " + err.Error())
			next.ServeHTTP(w, r)
			return
		}

		sess.Set("user", user)

		next.ServeHTTP(w, r)
	})
}

func Authorization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("In Authorization")

		sess, err := sessManager.SessionRead(r)
		if err != nil {
			log.Println("get sess : " + err.Error())
			common.RespondError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		fmt.Printf("Authorization ::: User : %v\n", sess.Get("user"))

		if ok := sess.Exist("user"); !ok {
			log.Println("user exist : " + err.Error())
			common.RespondError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		next.ServeHTTP(w, r)
	})
}
