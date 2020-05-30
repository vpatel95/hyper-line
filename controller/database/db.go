package database

import (
	"encoding/json"
	"io/ioutil"
	"log"

	"github.com/jinzhu/gorm"

	"hyperline-controller/env"
)

var (
	DB *gorm.DB
)

type DBConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Name     string `json:"dbname"`
	Charset  string `json:"charset"`
}

func GetConfig() *DBConfig {
	confFile, err := ioutil.ReadFile(env.DBConfig)
	if err != nil {
		log.Println("Error while reading session config from " + env.DBConfig)
		log.Println("Error : ", err)
		return nil
	}

	config := DBConfig{}

	if err := json.Unmarshal([]byte(confFile), &config); err != nil {
		log.Println(err.Error())
		return nil
	}

	return &config
}
