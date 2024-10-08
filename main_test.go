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
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
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

func oneTestApp(jwksServer, upstreamServer *httptest.Server, errorOnIllegalTenantValue bool) App {
	app := App{}
	app.WithConfig()
	app.Cfg.Web.JwksCertURL = jwksServer.URL
	app.WithJWKS()

	app.Cfg.Thanos.URL = upstreamServer.URL
	app.Cfg.Loki.URL = upstreamServer.URL
	app.Cfg.Thanos.TenantLabel = "tenant_id"
	app.Cfg.Thanos.ErrorOnIllegalTenantValue = errorOnIllegalTenantValue
	app.Cfg.Loki.TenantLabel = "tenant_id"
	app.Cfg.Loki.ErrorOnIllegalTenantValue = errorOnIllegalTenantValue

	cmh := ConfigMapHandler{
		labels: map[string]map[string]bool{
			"user":   {"tenant_id_u1": true, "tenant_id_u2": true},
			"group1": {"tenant_id_g1": true, "tenant_id_g2": true},
			"group2": {"tenant_id_g3": true, "tenant_id_g4": true},
		},
	}

	app.LabelStore = &cmh
	app.WithRoutes()

	return app
}

func setupTestMain() (App, App, map[string]string) {
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
			name:     "noTenant",
			Username: "not-a-valid-user",
			Email:    "test-email",
			Groups:   []string{},
		},
		{
			name:     "userTenant",
			Username: "user",
			Email:    "test-email",
			Groups:   []string{},
		},
		{
			name:     "groupTenant",
			Username: "not-a-valid-user",
			Email:    "test-email",
			Groups:   []string{"group1"},
		},
		{
			name:     "twoGroupsTenant",
			Username: "not-a-valid-user",
			Email:    "test-email",
			Groups:   []string{"group1", "group2"},
		},
		{
			name:     "userAndGroupTenant",
			Username: "user",
			Email:    "test-email",
			Groups:   []string{"group1", "group2"},
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
			return // we are in a test server, do nothing with the error
		}
	}))
	// defer jwksServer.Close()

	// Set up the upstream server
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Info().Msg("Fake metrics/logs server sending response.")
		_, err := fmt.Fprintln(w, "< fake upstream server response >")
		if err != nil {
			return // we are in a test server, do nothing with the error
		}
	}))
	// defer upstreamServer.Close()

	app1 := oneTestApp(jwksServer, upstreamServer, true)
	app2 := oneTestApp(jwksServer, upstreamServer, false)
	return app1, app2, tokens
}

func Test_reverseProxy(t *testing.T) {
	app1, app2, tokens := setupTestMain()
	var app *App

	cases := []struct {
		name                      string
		noSetAuthorization        bool
		authorization             string
		expectedStatus            int
		expectedBody              string
		URL                       string
		errorOnIllegalTenantValue bool
	}{
		{
			name:               "missing header",
			expectedStatus:     http.StatusForbidden,
			noSetAuthorization: true,
			URL:                "/api/v1/query_range",
			expectedBody:       "got no value for the HTTP header which is expected to contain the JWT\n",
		},
		{
			name:           "malformed header 1",
			expectedStatus: http.StatusForbidden,
			URL:            "/api/v1/query_range",
			authorization:  "B",
			expectedBody:   "failed to remove the bearer prefix from the JWT\n",
		},
		{
			name:           "malformed header 2",
			expectedStatus: http.StatusForbidden,
			URL:            "/api/v1/query_range",
			authorization:  "Bearer ",
			expectedBody:   "error parsing token\n",
		},
		{
			name:           "malformed header 3",
			expectedStatus: http.StatusForbidden,
			URL:            "/api/v1/query_range",
			authorization:  "Bearer skk",
			expectedBody:   "error parsing token\n",
		},
		{
			name:           "malformed header 3",
			expectedStatus: http.StatusForbidden,
			URL:            "/api/v1/query_range",
			authorization:  "Bearer abc def",
			expectedBody:   "error parsing token\n",
		},
		{
			name:           "user in token is invalid 1",
			expectedStatus: http.StatusForbidden,
			URL:            "/api/v1/query_range",
			authorization:  "Bearer " + tokens["noTenant"], // token configured with user name which is not in config store
			expectedBody:   "no tenant labels are configured for the user\n",
		},
		{
			name:           "user in token is invalid 2",
			authorization:  "Bearer " + tokens["noTenant"],                               // token configured with user name which is not in config store
			URL:            `/api/v1/query_range?query=up{tenant_id="forbidden_tenant"}`, // there is no value for tenant_id that should work
			expectedStatus: http.StatusForbidden,
			expectedBody:   "no tenant labels are configured for the user\n",
		},
		{
			name:           "empty query",
			authorization:  "Bearer " + tokens["userTenant"],
			URL:            `/api/v1/query_range`,
			expectedStatus: http.StatusOK,
			expectedBody:   "< fake upstream server response >\n",
		},
		{
			name:                      "multiple group membership with invalid tenant",
			authorization:             "Bearer " + tokens["groupTenant"],
			URL:                       `/api/v1/query_range?query=up{tenant_id="forbidden_tenant"}`,
			expectedStatus:            http.StatusForbidden,
			expectedBody:              `{"status":"error","errorType":"bad_data","error": "unauthorized tenant label value forbidden_tenant"}` + "\n",
			errorOnIllegalTenantValue: true,
		},
		{
			name:                      "user without groups with invalid tenant",
			authorization:             "Bearer " + tokens["userTenant"],
			URL:                       `/api/v1/query?query=up{tenant_id="another_forbidden_tenant"}`,
			expectedStatus:            http.StatusForbidden,
			expectedBody:              `{"status":"error","errorType":"bad_data","error": "unauthorized tenant label value another_forbidden_tenant"}` + "\n",
			errorOnIllegalTenantValue: true,
		},
		{
			name:                      "user query that results in no matched tenant label values and empty result",
			authorization:             "Bearer " + tokens["userTenant"],
			URL:                       `/api/v1/query?query=up{tenant_id=~"frogs!"}`,
			expectedStatus:            http.StatusOK,
			expectedBody:              "",
			errorOnIllegalTenantValue: false,
		},
		{
			name:                      "user query that results in no matched tenant label values and error",
			authorization:             "Bearer " + tokens["userTenant"],
			URL:                       `/api/v1/query?query=up{tenant_id=~"frogs!"}`,
			expectedStatus:            http.StatusForbidden,
			expectedBody:              `{"status":"error","errorType":"bad_data","error": "no tenant label values matched"}` + "\n",
			errorOnIllegalTenantValue: true,
		},
		{
			name:           "multiple group membership with single valid tenant value 1",
			authorization:  "Bearer " + tokens["groupTenant"],
			URL:            `/api/v1/query?query=up{tenant_id="tenant_id_g1"}`,
			expectedStatus: http.StatusOK,
			expectedBody:   "< fake upstream server response >\n",
		},
		{
			name:           "multiple group membership with single valid tenant value 2",
			authorization:  "Bearer " + tokens["twoGroupsTenant"],
			URL:            `/api/v1/query?query={tenant_id="tenant_id_g2"} != 1337`,
			expectedStatus: http.StatusOK,
			expectedBody:   "< fake upstream server response >\n",
		},
		{
			name:           "multiple group membership with multiple valid tenant values 1",
			authorization:  "Bearer " + tokens["twoGroupsTenant"],
			URL:            `/api/v1/query?query=up{tenant_id=~"tenant_id_g1|tenant_id_g4"}`,
			expectedStatus: http.StatusOK,
			expectedBody:   "< fake upstream server response >\n",
		},
		{
			name:           "multiple group membership with multiple valid tenant values 2",
			authorization:  "Bearer " + tokens["twoGroupsTenant"],
			URL:            `/api/v1/query?query={tenant_id=~"tenant_id_g1|tenant_id_g3"} != 1337`,
			expectedStatus: http.StatusOK,
			expectedBody:   "< fake upstream server response >\n",
		},
		{
			name:           "loki query_range with single valid tenant",
			authorization:  "Bearer " + tokens["twoGroupsTenant"],
			URL:            "/loki/api/v1/query_range?direction=backward&end=1690463973787000000&limit=1000&query=sum by (level) (count_over_time({tenant_id=\"tenant_id_g1\"} |= `path` |= `label` | json | line_format `{{.message}}` | json | line_format `{{.request}}` | json | line_format `{{.method | printf \"%-4s\"}} {{.path | printf \"%-60s\"}} {{.url | urldecode}}`[1m]))&start=1690377573787000000&step=60000ms",
			expectedStatus: http.StatusOK,
			expectedBody:   "< fake upstream server response >\n",
		},
		{
			name:           "loki index stats with single valid tenant",
			authorization:  "Bearer " + tokens["userTenant"],
			URL:            `/loki/api/v1/index/stats?query={tenant_id="tenant_id_u1"}&start=1690377573724000000&end=1690463973724000000`,
			expectedStatus: http.StatusOK,
			expectedBody:   "< fake upstream server response >\n",
		},
		{
			name:                      "loki query_range with single invalid tenant",
			authorization:             "Bearer " + tokens["userTenant"],
			URL:                       "/loki/api/v1/query_range?direction=backward&end=1690463973693000000&limit=10&query={tenant_id=\"forbidden_tenant\"} |= `path` |= `label` | json | line_format `{{.message}}` | json | line_format `{{.request}}` | json | line_format `{{.method}} {{.path}} {{.url | urldecode}}`&start=1690377573693000000&step=86400000ms",
			expectedStatus:            http.StatusForbidden,
			expectedBody:              "unauthorized tenant label value forbidden_tenant\n",
			errorOnIllegalTenantValue: true,
		},
		{
			name:                      "loki user without groups with invalid tenant empty result",
			authorization:             "Bearer " + tokens["userTenant"],
			URL:                       `/loki/api/v1/query_range?direction=backward&end=1690463973693000000&limit=10&query={tenant_id="forbidden_tenant"}`,
			expectedStatus:            http.StatusOK,
			expectedBody:              "",
			errorOnIllegalTenantValue: false,
		},
		{
			name:                      "loki user without groups with invalid tenant give error",
			authorization:             "Bearer " + tokens["userTenant"],
			URL:                       `/loki/api/v1/query_range?direction=backward&end=1690463973693000000&limit=10&query={tenant_id="forbidden_tenant"}`,
			expectedStatus:            http.StatusForbidden,
			expectedBody:              "unauthorized tenant label value forbidden_tenant\n",
			errorOnIllegalTenantValue: true,
		},
	}

	for _, tc := range cases {

		t.Run(tc.name, func(t *testing.T) {

			// Create a request
			req, err := http.NewRequest("GET", tc.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			// Set headers based on the test case.
			if !tc.noSetAuthorization {
				req.Header.Add("Authorization", tc.authorization)
			}

			// Prepare the response recorder
			rr := httptest.NewRecorder()

			// Choose which app to call based on configuration
			if tc.errorOnIllegalTenantValue {
				app = &app1
			} else {
				app = &app2
			}

			// Call the function
			log.Debug().Str("URL", tc.URL).Str("Authorization", tc.authorization).Msg("Request")
			app.e.ServeHTTP(rr, req)

			// Check the status code
			happy := assert.Equal(t, tc.expectedStatus, rr.Code)

			// Check the response body
			if tc.expectedBody != "" {
				happy = happy && assert.Contains(t, rr.Body.String(), tc.expectedBody)
			}

			log.Info().Bool("passed", happy).Str("name", tc.name).Msg("Reverse proxy test")
		})
	}
}

func TestIsAdminSkip(t *testing.T) {
	a := assert.New(t)

	app := &App{}
	app.WithConfig()
	app.Cfg.Admin.Bypass = true
	app.Cfg.Admin.Group = "gepardec-run-admins"
	token := &OAuthToken{Groups: []string{"gepardec-run-admins"}}
	a.True(isAdmin(*token, app))

	token.Groups = []string{"user"}
	a.False(isAdmin(*token, app))
}

func TestLogAndWriteError(t *testing.T) {
	a := assert.New(t)

	rw := httptest.NewRecorder()
	logAndWriteError(rw, http.StatusInternalServerError, nil, "test error")
	a.Equal(http.StatusInternalServerError, rw.Code)
	a.Equal("test error\n", rw.Body.String())
}
