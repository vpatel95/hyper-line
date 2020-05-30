package users

import (
	"log"
	"net/http"

	"hyperline-controller/app/lib/common"
	"hyperline-controller/app/lib/session"
)

type Session = session.Session

var SessManager = session.SessManager

func index(w http.ResponseWriter, r *http.Request) {
	log.Println("In User Get")
	common.RespondNotImplemented(w)
}

func get(w http.ResponseWriter, r *http.Request) {
	log.Println("In User GetAll")
	common.RespondNotImplemented(w)
}

func create(w http.ResponseWriter, r *http.Request) {
	log.Println("In User Create")
	common.RespondNotImplemented(w)
}

func update(w http.ResponseWriter, r *http.Request) {
	log.Println("In User Update")
	common.RespondNotImplemented(w)
}

func delete(w http.ResponseWriter, r *http.Request) {
	log.Println("In User Delete")
	common.RespondNotImplemented(w)
}