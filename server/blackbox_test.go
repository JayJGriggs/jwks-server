package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// These tests are "blackbox-ish": they call HTTP endpoints and validate responses.

func TestJWKSOnlyReturnsUnexpiredKey(t *testing.T) {
	ks, err := NewKeyStore()
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}

	mux := http.NewServeMux()
	RegisterRoutes(mux, ks)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	res, err := http.Get(ts.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(res.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}

	// Only active is unexpired, so exactly 1 key should show up.
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].KID != ks.Active.KID {
		t.Fatalf("expected active kid %s, got %s", ks.Active.KID, jwks.Keys[0].KID)
	}
}

func TestAuthNormalGivesUnexpiredTokenWithActiveKID(t *testing.T) {
	ks, _ := NewKeyStore()

	mux := http.NewServeMux()
	RegisterRoutes(mux, ks)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	res, err := http.Post(ts.URL+"/auth", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /auth: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	var out map[string]string
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	token := out["token"]
	if token == "" {
		t.Fatalf("missing token")
	}

	hb64, cb64, _, ok := ParseJWTParts(token)
	if !ok {
		t.Fatalf("token not 3 parts")
	}

	dec := base64.RawURLEncoding

	hjson, err := dec.DecodeString(hb64)
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	cjson, err := dec.DecodeString(cb64)
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}

	var hdr map[string]any
	_ = json.Unmarshal(hjson, &hdr)

	if hdr["kid"] != ks.Active.KID {
		t.Fatalf("expected kid %s, got %v", ks.Active.KID, hdr["kid"])
	}

	var claims map[string]any
	_ = json.Unmarshal(cjson, &claims)

	expF, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("exp missing")
	}
	exp := int64(expF)
	if exp <= time.Now().UTC().Unix() {
		t.Fatalf("expected token to be unexpired, exp=%d", exp)
	}
}

func TestAuthExpiredQueryGivesExpiredTokenWithExpiredKID(t *testing.T) {
	ks, _ := NewKeyStore()

	mux := http.NewServeMux()
	RegisterRoutes(mux, ks)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	res, err := http.Post(ts.URL+"/auth?expired=true", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /auth?expired=true: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	var out map[string]string
	_ = json.NewDecoder(res.Body).Decode(&out)
	token := out["token"]

	hb64, cb64, _, ok := ParseJWTParts(token)
	if !ok {
		t.Fatalf("token not 3 parts")
	}

	dec := base64.RawURLEncoding
	hjson, _ := dec.DecodeString(hb64)
	cjson, _ := dec.DecodeString(cb64)

	var hdr map[string]any
	_ = json.Unmarshal(hjson, &hdr)

	if hdr["kid"] != ks.Expired.KID {
		t.Fatalf("expected expired kid %s, got %v", ks.Expired.KID, hdr["kid"])
	}

	var claims map[string]any
	_ = json.Unmarshal(cjson, &claims)

	expF, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("exp missing")
	}
	exp := int64(expF)
	if exp >= time.Now().UTC().Unix() {
		t.Fatalf("expected token to be expired, exp=%d", exp)
	}
}

func TestWrongMethodsReturn405(t *testing.T) {
	ks, _ := NewKeyStore()

	mux := http.NewServeMux()
	RegisterRoutes(mux, ks)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// GET /auth should be 405
	res1, _ := http.Get(ts.URL + "/auth")
	res1.Body.Close()
	if res1.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for GET /auth, got %d", res1.StatusCode)
	}

	// POST jwks should be 405
	res2, _ := http.Post(ts.URL+"/.well-known/jwks.json", "application/json", nil)
	res2.Body.Close()
	if res2.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for POST jwks, got %d", res2.StatusCode)
	}
}
