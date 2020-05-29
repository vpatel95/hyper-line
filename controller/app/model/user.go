package model

import (
	_ "time"

	"github.com/jinzhu/gorm"
)

type JSON = map[string]interface{}

type User struct {
	gorm.Model
	Name     string `gorm:"column:name" json:"name"`
	Email    string `gorm:"column:email;unique_index" json:"email"`
	Username string `gorm:"column:username;unique_index" json:"username"`
	Password string `gorm:"column:password;not null" json:"password"`
}

func (u *User) Serialize() JSON {
	return JSON{
		"id":       u.ID,
		"name":     u.Name,
		"username": u.Username,
		"email":    u.Email,
	}
}

// User Migration changes. Update this whenever user table is modified
func MigrateUser(db *gorm.DB) *gorm.DB {
	db.AutoMigrate(&User{})
	return db
}
