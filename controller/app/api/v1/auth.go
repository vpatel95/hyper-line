package apiv1

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"

	"hyperline-controller/app/api/common"
	"hyperline-controller/app/model"
	"hyperline-controller/app/validation"
	"hyperline-controller/database"
)

type JSON = map[string]interface{}
type User = model.User

func hash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

func matchHash(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateToken(data JSON) (string, error) {
	date := time.Now().Add(time.Hour * 24 * 7)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user":    data,
		"expires": date.Unix(),
	})

	pwd, _ := os.Getwd()
	keyPath := pwd + "/jwtsecret.key"

	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		fmt.Println("GenerateToken : Key file read error = " + err.Error())
		return "", err
	}

	tokenStr, err := token.SignedString(key)
	if err != nil {
		fmt.Println("GenerateToken : Token string error = " + err.Error())
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
	fmt.Println("In User Create")
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
	fmt.Println("In User Login")

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

	cookie := CreateCookie("token", token, 60*60*24*7, "/", "", false, true)
	http.SetCookie(w, &cookie)

	common.RespondJSON(w, http.StatusCreated, JSON{
		"message": "success",
	})
}

func SetAuthRoutes(router *mux.Router) {
	authRoute := router.PathPrefix("/auth").Subrouter()

	common.Post(authRoute, "/login", login)
	common.Post(authRoute, "/register", register)
}
