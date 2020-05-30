package validation

import (
	"errors"

	valid "github.com/asaskevich/govalidator"

	"hyperline-controller/database"
	"hyperline-controller/app/model"
)

var (
	// Null Error messages
	ErrNullName     = errors.New("Name cannot be empty")
	ErrNullUsername = errors.New("Username cannot be empty")
	ErrNullEmail    = errors.New("Email cannot be empty")
	ErrNullPassword = errors.New("Password cannot be empty")

	// Invalid Error messages
	ErrInvalidEmail    = errors.New("Invalid email")
	ErrInvalidUsername = errors.New("Invalid username.")

	// Already exists Error messages
	ErrEmailExists    = errors.New("Email already exists")
	ErrUsernameExists = errors.New("Username already exists")
)

type User = model.User

func ValidateCreateUser(user model.User) error {
	var exists User
	db := database.DB

	if valid.IsNull(user.Name) {
		return ErrNullName
	}

	if valid.IsNull(user.Email) {
		return ErrNullEmail
	}

	if !valid.IsEmail(user.Email) {
		return ErrInvalidEmail
	}

	if err := db.Where("email = ?", user.Email).First(&exists).Error; err == nil {
		return ErrEmailExists
	}

	if valid.IsNull(user.Username) {
		return ErrNullUsername
	}

	if !valid.IsAlphanumeric(user.Username) {
		return ErrInvalidUsername
	}

	if err := db.Where("username = ?", user.Username).First(&exists).Error; err == nil {
		return ErrUsernameExists
	}

	if valid.IsNull(user.Password) {
		return ErrNullPassword
	}

	return nil
}

func ValidateLoginUser(username string, password string) error {

	if valid.IsNull(username) {
		return ErrNullUsername
	}

	if valid.IsNull(password) {
		return ErrNullPassword
	}

	return nil
}
