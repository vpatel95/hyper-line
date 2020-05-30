package auth

import (
	"github.com/gorilla/mux"

	"hyperline-controller/app/lib/common"
)

func Routes(router *mux.Router) {
	route := router.PathPrefix("/auth").Subrouter()

	common.Post(route, "/login", login)
	common.Post(route, "/register", register)
}
