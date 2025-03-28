package main

import (
	"encoding/json"
	"log"
	"net/http"
)

// Add a simple in-memory user store for demonstration purposes
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var users = map[string]string{} // username -> password

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var payload User
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if _, exists := users[payload.Username]; exists {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	users[payload.Username] = payload.Password
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func isAuthenticatedHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"isAuthenticated": true})
}

func main() {
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/authenticated", isAuthenticatedHandler)

	log.Println("Server is running on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
