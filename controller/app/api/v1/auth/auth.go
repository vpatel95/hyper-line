package auth

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"path/filepath"

	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"

	"hyperline-controller/app/lib/common"
	sess "hyperline-controller/app/lib/session"
	"hyperline-controller/app/lib/validation"
	"hyperline-controller/app/model"
	"hyperline-controller/database"
	"hyperline-controller/env"
)

type JSON = map[string]interface{}
type User = model.User

var sessManager = sess.SessManager

func hash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

func matchHash(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateToken(data JSON) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": data,
	})

	keyPath := filepath.Join(env.JWTSecret)

	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		log.Println("GenerateToken : Key file read error = " + err.Error())
		return "", err
	}

	tokenStr, err := token.SignedString(key)
	if err != nil {
		log.Println("GenerateToken : Token string error = " + err.Error())
	}

	return tokenStr, err
}

func CreateCookie(name, value string, maxAge int, path, domain string,
	secure, httpOnly bool) http.Cookie {

	return http.Cookie{
		Name:     name,
		Value:    url.QueryEscape(value),
		MaxAge:   maxAge,
		Path:     path,
		Domain:   domain,
		Secure:   secure,
		HttpOnly: httpOnly,
	}
}

func register(w http.ResponseWriter, r *http.Request) {
	log.Println("In User Create")
	var user User
	var err error

	db := database.DB

	if err = json.NewDecoder(r.Body).Decode(&user); err != nil {
		common.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.Body.Close()

	if err = validation.ValidateCreateUser(user); err != nil {
		common.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if user.Password, err = hash(user.Password); err != nil {
		common.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	db.Create(&user)

	common.RespondJSON(w, http.StatusCreated, JSON{
		"message": "success",
		"data":    user.Serialize(),
	})
}

func login(w http.ResponseWriter, r *http.Request) {
	log.Println("In User Login")

	type RequestBody struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	var err error
	var user User
	var body RequestBody

	db := database.DB

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		common.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.Body.Close()

	if err = validation.ValidateLoginUser(body.Username, body.Password); err != nil {
		common.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err = db.Where("username = ?", body.Username).First(&user).Error; err != nil {
		common.RespondError(w, http.StatusNotFound, err.Error())
		return
	}

	if !matchHash(body.Password, user.Password) {
		common.RespondError(w, http.StatusUnauthorized, "Invalid Password")
		return
	}

	serializedUser := user.Serialize()
	token, _ := generateToken(serializedUser)

	cookie := CreateCookie(sessManager.Config.CookieName, token,
		sessManager.Config.CookieLifetime, "/", "", false, true)
	http.SetCookie(w, &cookie)

	common.RespondJSON(w, http.StatusCreated, JSON{
		"message": "success",
	})
}
