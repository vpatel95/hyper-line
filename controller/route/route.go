package route

import (
	"hyperline-controller/app/api"

	"github.com/gorilla/mux"
)

var (
	Router *mux.Router
)

func SetRoutes() {
	Router = mux.NewRouter()
	api.SetRoutes(Router)
}
