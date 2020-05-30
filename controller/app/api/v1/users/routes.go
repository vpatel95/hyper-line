package users

import (
	"github.com/gorilla/mux"

	"hyperline-controller/app/api/v1/middleware"
	"hyperline-controller/app/lib/common"
)

func Routes(router *mux.Router) {
	route := router.PathPrefix("/user").Subrouter()
	route.Use(middleware.ValidateSessionID, middleware.Authorization)

	common.Get(route, "/{username}", get)
	common.Get(route, "/all", index)
	common.Post(route, "/create", create)
	common.Put(route, "/{username}", update)
	common.Delete(route, "/{username}", delete)
}
