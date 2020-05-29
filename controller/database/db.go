package database

import (
	"github.com/jinzhu/gorm"
)

var (
	DB *gorm.DB
)

type DBConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	Name     string
	Charset  string
}

func GetConfig() *DBConfig {
	return &DBConfig{
		Host:     "localhost",
		Port:     3306,
		Username: "hyperline",
		Password: "hyperline",
		Name:     "hyperline",
		Charset:  "utf8",
	}
}
