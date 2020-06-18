package model

import (
	_ "time"

	"github.com/jinzhu/gorm"

	"hyperline-controller/database"
)

var (
	db = database.DB
)

type User struct {
	gorm.Model
	Name     string `gorm:"column:name" json:"name"`
	Email    string `gorm:"column:email;unique_index" json:"email"`
	Username string `gorm:"column:username;unique_index" json:"username"`
	Password string `gorm:"column:password;not null" json:"password"`

	Tasks   []Task
	Workers []Worker
}

func (u *User) Serialize() JSON {
	return JSON{
		"id":       u.ID,
		"name":     u.Name,
		"username": u.Username,
		"email":    u.Email,
	}
}

func (u *User) Load(data JSON) {
	u.ID = data["id"].(uint)
	u.Name = data["name"].(string)
	u.Username = data["username"].(string)
	u.Email = data["email"].(string)
}

func (u *User) GetTasks() []Task {
	var tasks []Task
	db.Model(&u).Related(&tasks)

	return tasks
}

func (u *User) GetWorkers() []Worker {
	var workers []Worker
	db.Model(&u).Related(&workers)

	return workers
}

// User Migration changes. Update this whenever user table is modified
func MigrateUser(db *gorm.DB) *gorm.DB {
	db.AutoMigrate(&User{})
	return db
}
