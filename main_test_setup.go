package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
)

func genJWKS(username, email string, groups []string, pk *ecdsa.PrivateKey) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"preferred_username": username,
		"email":              email,
		"groups":             groups,
	})
	token.Header["kid"] = "testKid"
	return token.SignedString(pk)
}

func makeTestApp(jwksServer, upstreamServer *httptest.Server, errorOnIllegalTenantValue bool, adminGroup bool, magicValueBypass bool, headerBypass bool) App {
	app := App{}
	app.WithConfig() // note: sets logging level based on config.yaml
	app.Cfg.Web.JwksCertURL = jwksServer.URL
	app.WithJWKS()

	app.Cfg.Thanos.URL = upstreamServer.URL
	app.Cfg.Loki.URL = upstreamServer.URL
	app.Cfg.Thanos.TenantLabel = "tenant_id" // this is the label (query filter key) that has meaning for test cases
	app.Cfg.Thanos.ErrorOnIllegalTenantValue = errorOnIllegalTenantValue
	app.Cfg.Loki.TenantLabel = "tenant_id" // this is the label (query filter key) that has meaning for test cases
	app.Cfg.Loki.ErrorOnIllegalTenantValue = errorOnIllegalTenantValue

	app.Cfg.Admin.GroupBypass = adminGroup
	if adminGroup {
		app.Cfg.Admin.Group = "admingroupname" // admingroupname matches tenant defined in setupReverseProxyTest()
	}

	app.Cfg.Admin.MagicValueBypass = magicValueBypass
	if magicValueBypass {
		app.Cfg.Admin.MagicValue = "<(magicadminvalue)>" // <(magicadminvalue)> matches user defined below
	}

	app.Cfg.Admin.HeaderBypass = headerBypass
	if headerBypass {
		app.Cfg.Admin.Header.Key = "MagicHeader"
		app.Cfg.Admin.Header.Value = "notaverygoodsecret"
	}

	// this is our config defining what tenant label values are valid for the test cases
	// the tenant label name is set above (to "tenant_id")
	// this is the linear (original) CM format, see labelstore_test.go for an inline example of each format
	cmh := ConfigMapHandler{
		labels: map[string]map[string]bool{
			"valid-user":       {"tenant_id_u1": true, "tenant_id_u2": true},
			"valid-user-magic": {"tenant_id_u1": true, "tenant_id_u2": true, "<(magicadminvalue)>": true},
			"group1":           {"tenant_id_g1": true, "tenant_id_g2": true},
			"group2":           {"tenant_id_g3": true, "tenant_id_g4": true},
		},
	}

	app.LabelStore = &cmh
	app.WithRoutes()

	return app
}

func setupReverseProxyTest() (map[string]App, map[string]string) {
	// Generate a new private key.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate private key: %s\n", err))
	}

	// Encode the private key to PEM format.
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal private key: %s\n", err))
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Encode the public key to PEM format.
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal public key: %s\n", err))
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Generate a key pair
	pk, _ := jwt.ParseECPrivateKeyFromPEM(privateKeyPEM)
	pubkey, _ := jwt.ParseECPublicKeyFromPEM(publicKeyPEM)

	jwks := []struct {
		name     string
		Username string
		Email    string
		Groups   []string
	}{
		{
			name:     "invalidTenant",
			Username: "not-a-valid-user",
			Email:    "test-email",
			Groups:   []string{},
		},
		{
			name:     "invalidTenantWithGroups",
			Username: "not-a-valid-user",
			Email:    "test-email",
			Groups:   []string{"invalid-group1", "invalid-group2"},
		},
		{
			name:     "userTenant",
			Username: "valid-user", // defined as a valid user in CM in makeTestApp()
			Email:    "test-email",
			Groups:   []string{},
		},
		{
			name:     "groupTenant",
			Username: "not-a-valid-user",
			Email:    "test-email",
			Groups:   []string{"group1"}, // defined as a valid group in CM in makeTestApp()
		},
		{
			name:     "twoGroupsTenant",
			Username: "not-a-valid-user",
			Email:    "test-email",
			Groups:   []string{"group1", "group2"}, // defined as two valid groups in CM in makeTestApp()
		},
		{
			name:     "userAndGroupTenant",
			Username: "valid-user", // defined as a valid user in CM in makeTestApp()
			Email:    "test-email",
			Groups:   []string{"group1", "group2"}, // defined as two valid groups in CM in makeTestApp()
		},
		{
			name:     "adminBypassTenant",
			Username: "adminuser",
			Email:    "test-email",
			Groups:   []string{"admingroupname", "group1", "group2"}, // admingroupname matches group set in makeTestApp()
		},
		{
			name:     "magicBypassTenant",
			Username: "valid-user-magic", // defined as a valid user in CM in makeTestApp() with magic value access
			Email:    "test-email",
			Groups:   []string{"whatever", "something"},
		},
		{
			name:     "invalidMagicBypassTenant",
			Username: "invalid-user",
			Email:    "test-email",
			Groups:   []string{"<(magicadminvalue)>"}, // <(magicadminvalue)> matches value set in makeTestApp(), expected to not work here
		},
	}
	tokens := make(map[string]string, len(jwks))
	for _, jwk := range jwks {
		token, _ := genJWKS(jwk.Username, jwk.Email, jwk.Groups, pk)
		tokens[jwk.name] = token
	}

	// Base64url encoding
	x := base64.RawURLEncoding.EncodeToString(pubkey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(pubkey.Y.Bytes())

	// Set up the JWKS server
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Info().Msg("Fake JWKS server sending response.")
		_, err := fmt.Fprintf(w, `{"keys":[{"kty":"EC","kid":"testKid","alg":"ES256","use":"sig","x":"%s","y":"%s","crv":"P-256"}]}`, x, y)
		if err != nil {
			log.Error().Msg("Some kind of error in the fake JWKS server.")
			return // we are in a test server, do nothing with the error
		}
	}))
	// defer jwksServer.Close()

	// Set up the upstream server
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Info().Msg("Fake metrics/logs server sending response.")
		_, err := fmt.Fprintln(w, "< fake upstream server response >")
		if err != nil {
			log.Error().Msg("Some kind of error in the fake metrics/logs server.")
			return // we are in a test server, do nothing with the error
		}
	}))
	// defer upstreamServer.Close()

	appmap := map[string]App{
		"bad_tenant_tolerant":   makeTestApp(jwksServer, upstreamServer, false, true, false, false),
		"bad_tenant_intolerant": makeTestApp(jwksServer, upstreamServer, true, true, false, false),
		"only_magic_val":        makeTestApp(jwksServer, upstreamServer, false, false, true, false),
		"group_or_header":       makeTestApp(jwksServer, upstreamServer, false, true, false, true),
	}
	return appmap, tokens
}
