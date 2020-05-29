package app

import (
	"fmt"
	"log"
	"net/http"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"

	"hyperline-controller/app/model"
	db "hyperline-controller/database"
	"hyperline-controller/route"
)

type App struct {
	Host string
	Port int
}

func Init(conf *db.DBConfig) {
	var err error

	dbURI := fmt.Sprintf("%s:%s@(%s:%d)/%s?charset=%s&parseTime=true&loc=Local",
		conf.Username, conf.Password,
		conf.Host, conf.Port,
		conf.Name, conf.Charset)

	db.DB, err = gorm.Open("mysql", dbURI)
	if err != nil {
		fmt.Println(err)
		log.Fatal("Failed to connect database")
	}

	db.DB = model.Migration(db.DB)
	route.SetRoutes()
}

func (a *App) Run() {
	conf := db.GetConfig()
	Init(conf)

	appURI := fmt.Sprintf("%s:%d", a.Host, a.Port)

	http.Handle("/", route.Router)

	log.Println("Starting server on : http://" + appURI)
	log.Fatal(http.ListenAndServe(appURI, route.Router))
}
