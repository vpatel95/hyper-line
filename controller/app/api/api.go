package api

import (
	"github.com/gorilla/mux"

	"hyperline-controller/app/api/v1"
)

func SetRoutes(router *mux.Router) {
	api := router.PathPrefix("/api").Subrouter()

	apiv1.SetRoutes(api)
}
