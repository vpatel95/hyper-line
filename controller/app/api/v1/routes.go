package apiv1

import (
	"github.com/gorilla/mux"

	"hyperline-controller/app/api/v1/auth"
	"hyperline-controller/app/api/v1/users"
)

func SetRoutes(router *mux.Router) {
	route := router.PathPrefix("/v1").Subrouter()

	auth.Routes(route)
	users.Routes(route)
}
