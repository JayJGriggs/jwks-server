package server

import (
	"encoding/json"
	"net/http"
	"time"
)

// RegisterRoutes sets up endpoints required by the rubric.
func RegisterRoutes(mux *http.ServeMux, ks *KeyStore) {
	// JWKS endpoint (public keys)
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed) // 405
			return
		}
		handleJWKS(w, ks)
	})

	// Auth endpoint (issues JWT)
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed) // 405
			return
		}
		handleAuth(w, r, ks)
	})
}

// handleJWKS returns only keys that are NOT expired.
func handleJWKS(w http.ResponseWriter, ks *KeyStore) {
	now := time.Now().UTC()
	resp := JWKS{Keys: []JWK{}}

	// Only serve unexpired keys:
	if now.Before(ks.Active.ExpiresAt) {
		pub := ks.Active.Priv.PublicKey
		resp.Keys = append(resp.Keys, rsaPublicToJWK(ks.Active.KID, pub.N, pub.E))
	}
	if now.Before(ks.Expired.ExpiresAt) {
		pub := ks.Expired.Priv.PublicKey
		resp.Keys = append(resp.Keys, rsaPublicToJWK(ks.Expired.KID, pub.N, pub.E))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleAuth issues a token.
// - POST /auth -> normal token (active key)
// - POST /auth?expired=true -> expired token (expired key + exp in the past)
func handleAuth(w http.ResponseWriter, r *http.Request, ks *KeyStore) {
	expiredMode := false

	// Requirement: "If the expired query parameter is present..."
	// That means: /auth?expired or /auth?expired=true both count.
	if _, ok := r.URL.Query()["expired"]; ok {
		expiredMode = true
	}

	keyToUse := ks.Active
	if expiredMode {
		keyToUse = ks.Expired
	}

	token, err := IssueJWT(keyToUse, expiredMode)
	if err != nil {
		http.Error(w, "could not create token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
}
