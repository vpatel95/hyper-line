package apiv1

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"hyperline-controller/app/api/common"
)

func getUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("In User Get")
	common.RespondNotImplemented(w)
}

func getAllUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("In User GetAll")
	common.RespondNotImplemented(w)
}

func createUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("In User Create")
	common.RespondNotImplemented(w)
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("In User Update")
	common.RespondNotImplemented(w)
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("In User Delete")
	common.RespondNotImplemented(w)
}

func SetUserRoutes(router *mux.Router) {
	userRoute := router.PathPrefix("/user").Subrouter()
	userRoute.Use(common.Auth, common.UserAuth)

	common.Get(userRoute, "/{username}", getUser)
	common.Get(userRoute, "/all", getAllUser)
	common.Post(userRoute, "/create", createUser)
	common.Put(userRoute, "/{username}", updateUser)
	common.Delete(userRoute, "/{username}", deleteUser)
}
