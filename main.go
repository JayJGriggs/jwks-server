package main

import (
	"log"
	"net/http"

	"jwks-server/server"
)

func main() {
	// Create our in-memory keys (1 active + 1 expired)
	keyStore, err := server.NewKeyStore()
	if err != nil {
		log.Fatalf("failed to create keys: %v", err)
	}

	// Register HTTP routes
	mux := http.NewServeMux()
	server.RegisterRoutes(mux, keyStore)

	// IMPORTANT: requirement says port 8080
	log.Println("Server running on http://localhost:8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("server crashed: %v", err)
	}
}
