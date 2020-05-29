package apiv1

import (
	"github.com/gorilla/mux"
)

func SetRoutes(router *mux.Router) {
	apiv1 := router.PathPrefix("/v1").Subrouter()

	SetAuthRoutes(apiv1)
	SetUserRoutes(apiv1)
}
