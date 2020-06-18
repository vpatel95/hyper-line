package users

import (
	"github.com/gorilla/mux"

	"hyperline-controller/app/api/v1/middleware"
	"hyperline-controller/app/lib/common"
)

func Routes(router *mux.Router) {
	route := router.PathPrefix("/user").Subrouter()
	route.Use(middleware.ValidateSessionID, middleware.Authorization)

	common.Get(route, "/{id}", get)
	common.Get(route, "/all", index)
	common.Post(route, "/create", create)
	common.Put(route, "/{id}", update)
	common.Delete(route, "/{id}", delete)
}
