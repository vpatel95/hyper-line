package common

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

type ReqHandlerFunc func(w http.ResponseWriter, r *http.Request)

// Request Handler Helper Functions

// Get Request Wrapper
func Get(r *mux.Router, path string, fn ReqHandlerFunc) {
	r.HandleFunc(path, fn).Methods("GET")
}

// Post Request Wrapper
func Post(r *mux.Router, path string, fn ReqHandlerFunc) {
	r.HandleFunc(path, fn).Methods("POST")
}

// Put Request Wrapper
func Put(r *mux.Router, path string, fn ReqHandlerFunc) {
	r.HandleFunc(path, fn).Methods("PUT")
}

// Delete Request Wrapper
func Delete(r *mux.Router, path string, fn ReqHandlerFunc) {
	r.HandleFunc(path, fn).Methods("DELETE")
}

// Response Helper Functions

// Send a JSON Response
func RespondJSON(w http.ResponseWriter, status int, payload interface{}) {
	res, err := json.Marshal(payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write([]byte(res))
}

// Error response wrapper for JSON Response
func RespondError(w http.ResponseWriter, code int, message string) {
	RespondJSON(w, code, map[string]string{"message": message})
}

// Not Implemented response wrapper for JSON Response
func RespondNotImplemented(w http.ResponseWriter) {
	RespondJSON(w, http.StatusInternalServerError, map[string]string{"message": "Not yet implemented"})
}

// Set Cookie in HTTP Response
func SetCookie(w http.ResponseWriter, name string, value string) {
	expire := time.Now().Add(24 * 60 * time.Second)
	cookie := http.Cookie{
		Name:    name,
		Value:   value,
		Expires: expire,
	}
	http.SetCookie(w, &cookie)
}
