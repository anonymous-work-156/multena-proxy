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

func makeTestApp(jwksServer, upstreamServer *httptest.Server, errorOnIllegalTenantValue bool, adminGroup bool, magicValueBypass bool, headerBypass bool) App {
	app := App{}
	app.WithConfig()
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
		app.Cfg.Admin.Group = "admingroupname" // admingroupname matches tenant defined in setupTestMain()
	}

	app.Cfg.Admin.MagicValueBypass = magicValueBypass
	if magicValueBypass {
		app.Cfg.Admin.MagicValue = "<(magicadminvalue)>" // <(magicadminvalue)> matches tenant defined in setupTestMain()
	}

	app.Cfg.Admin.HeaderBypass = headerBypass
	if headerBypass {
		app.Cfg.Admin.Header.Key = "MAGICHEADER"
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

func setupTestMain() (map[string]App, map[string]string) {
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

	appmap := map[string]App{
		"bad_tenant_tolerant":   makeTestApp(jwksServer, upstreamServer, false, true, false, false),
		"bad_tenant_intolerant": makeTestApp(jwksServer, upstreamServer, true, true, false, false),
		"only_magic_val":        makeTestApp(jwksServer, upstreamServer, false, false, true, false),
		"group_or_header":       makeTestApp(jwksServer, upstreamServer, false, true, false, true),
	}
	return appmap, tokens
}

func Test_reverseProxy(t *testing.T) {

	log.Info().Caller().Msg("Start Test_reverseProxy().")
	defer log.Info().Msg("End Test_reverseProxy().")

	appmap, tokens := setupTestMain()

	type ExpectedResult struct {
		matchingApp string
		status      int
		body        string
	}

	type TestHeader struct {
		key string
		val string
	}

	type TestCase struct {
		name                string
		baseName            string
		URL                 string
		noSetAuthorization  bool
		authorizationHeader string
		header              TestHeader
		expectedResults     []ExpectedResult
	}

	cases := []TestCase{
		{
			baseName: "wrong_path",
			URL:      "/foo/bar",
			expectedResults: []ExpectedResult{{
				matchingApp: "*",
				status:      http.StatusNotFound,
				body:        "not a registered route\n", // we hope to hit our logEverythingElseHandler
			}},
		},
		{
			baseName:           "no_headers_at_all",
			URL:                "/api/v1/query_range",
			noSetAuthorization: true,
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusForbidden,
					body:        "got no value for the HTTP header which is expected to contain the JWT\n",
				},
			},
		},
		{
			baseName:           "missing_auth_header",
			URL:                "/api/v1/query_range",
			noSetAuthorization: true,
			header:             TestHeader{key: "MAGICHEADER", val: "notaverygoodsecret"}, // one app should pass due to this
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusForbidden,
					body:        "got no value for the HTTP header which is expected to contain the JWT\n",
				},
				{
					matchingApp: "group_or_header",
					status:      http.StatusOK,
					body:        "< fake upstream server response >\n",
				},
			},
		},
		{
			baseName:            "malformed_auth_header_1",
			URL:                 "/api/v1/query_range",
			authorizationHeader: "B",
			header:              TestHeader{key: "MAGICHEADER", val: "notaverygoodsecret"}, // one app should pass due to this
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusForbidden,
					body:        "failed to remove the bearer prefix from the JWT\n",
				},
				{
					matchingApp: "group_or_header",
					status:      http.StatusOK,
					body:        "< fake upstream server response >\n",
				},
			},
		},
		{
			baseName:            "malformed_auth_header_2",
			URL:                 "/api/v1/query_range",
			authorizationHeader: "Bearer ",
			header:              TestHeader{key: "MAGICHEADER", val: "notaverygoodsecret"}, // one app should pass due to this
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusForbidden,
					body:        "error parsing token\n",
				},
				{
					matchingApp: "group_or_header",
					status:      http.StatusOK,
					body:        "< fake upstream server response >\n",
				},
			},
		},
		{
			baseName:            "malformed_headers_1",
			URL:                 "/api/v1/query_range",
			authorizationHeader: "Bearer skk",
			header:              TestHeader{key: "MAGICHEADER", val: "wrong"},
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusForbidden,
					body:        "error parsing token\n",
				},
			},
		},
		{
			baseName:            "malformed_headers_2",
			URL:                 "/api/v1/query_range",
			authorizationHeader: "Bearer abc def",
			header:              TestHeader{key: "MAGICHEADER", val: ""},
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusForbidden,
					body:        "error parsing token\n",
				},
			},
		},
		{
			baseName:            "user_in_token_is_invalid_1",
			URL:                 "/api/v1/query_range",
			authorizationHeader: "Bearer " + tokens["invalidTenant"], // token configured with user name which is not in config store
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusForbidden,
					body:        "no tenant labels are configured for the user\n",
				},
				{
					matchingApp: "group_or_header",
					status:      http.StatusOK,
					body:        "< fake upstream server response >\n",
				},
			},
		},
		{
			baseName:            "user_in_token_is_invalid_2",
			URL:                 `/api/v1/query_range?query=up{tenant_id="forbidden_tenant"}`, // there is no value for tenant_id that should work
			authorizationHeader: "Bearer " + tokens["invalidTenant"],                          // token configured with user name which is not in config store
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusForbidden,
					body:        "no tenant labels are configured for the user\n",
				},
				{
					matchingApp: "group_or_header",
					status:      http.StatusOK,
					body:        "< fake upstream server response >\n",
				},
			},
		},
		{
			baseName:            "empty_query",
			URL:                 `/api/v1/query_range`,
			authorizationHeader: "Bearer " + tokens["userTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "< fake upstream server response >\n",
				},
			},
		},
		{
			baseName:            "multiple_group_membership_with_invalid_tenant",
			URL:                 `/api/v1/query_range?query=up{tenant_id="forbidden_tenant"}`,
			authorizationHeader: "Bearer " + tokens["groupTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "",
				},
				{
					matchingApp: "bad_tenant_intolerant",
					status:      http.StatusForbidden,
					body:        `{"status":"error","errorType":"bad_data","error": "unauthorized tenant label value"}` + "\n",
				},
				{
					matchingApp: "header",
					status:      http.StatusOK,
					body:        "< fake upstream server response >\n",
				},
			},
		},
		{
			baseName:            "user_without_groups_with_invalid_tenant",
			URL:                 `/api/v1/query?query=up{tenant_id="another_forbidden_tenant"}`,
			authorizationHeader: "Bearer " + tokens["userTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "",
				},
				{
					matchingApp: "bad_tenant_intolerant",
					status:      http.StatusForbidden,
					body:        `{"status":"error","errorType":"bad_data","error": "unauthorized tenant label value"}` + "\n",
				},
				{
					matchingApp: "header",
					status:      http.StatusOK,
					body:        "< fake upstream server response >\n",
				},
			},
		},
		{
			baseName:            "user_query_that_results_in_no_matched_tenant_label_values_and_empty_result",
			URL:                 `/api/v1/query?query=up{tenant_id=~"frogs!"}`,
			authorizationHeader: "Bearer " + tokens["userTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "",
				},
				{
					matchingApp: "bad_tenant_intolerant",
					status:      http.StatusForbidden,
					body:        `{"status":"error","errorType":"bad_data","error": "no tenant label values matched"}` + "\n",
				},
				{
					matchingApp: "header",
					status:      http.StatusOK,
					body:        "< fake upstream server response >\n",
				},
			},
		},
		{
			baseName:            "group_membership_with_single_valid_tenant_value",
			URL:                 `/api/v1/query?query=up{tenant_id="tenant_id_g1"}`,
			authorizationHeader: "Bearer " + tokens["groupTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "< fake upstream server response >\n",
				},
			},
		},
		{
			baseName:            "multiple_group_membership_with_single_valid_tenant_value",
			URL:                 `/api/v1/query?query={tenant_id="tenant_id_g2"} != 1337`,
			authorizationHeader: "Bearer " + tokens["twoGroupsTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "< fake upstream server response >\n",
				},
			},
		},
		{
			baseName:            "multiple_group_membership_with_multiple_valid_tenant_values_1",
			URL:                 `/api/v1/query?query=up{tenant_id=~"tenant_id_g1|tenant_id_g4"}`,
			authorizationHeader: "Bearer " + tokens["twoGroupsTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "< fake upstream server response >\n",
				},
			},
		},
		{
			baseName:            "multiple_group_membership_with_multiple_valid_tenant_values_2",
			URL:                 `/api/v1/query?query={tenant_id=~"tenant_id_g1|tenant_id_g3"} != 1337`,
			authorizationHeader: "Bearer " + tokens["twoGroupsTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "< fake upstream server response >\n",
				},
			},
		},
		{
			baseName:            "strange_query_with_magic_value_bypass_1",
			URL:                 `/api/v1/query?query=count(count({__name__!="",tenant_id="bob"}) by (__name__))`, // any tenant value works
			authorizationHeader: "Bearer " + tokens["magicBypassTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "",
				},
				{
					matchingApp: "only_magic_val",
					status:      http.StatusOK,
					body:        "< fake upstream server response >\n",
				},
				{
					matchingApp: "bad_tenant_intolerant",
					status:      http.StatusForbidden,
					body:        `{"status":"error","errorType":"bad_data","error": "no tenant label values matched"}` + "\n",
				},
			},
		},
		{
			baseName:            "strange_query_with_magic_value_bypass_2",
			URL:                 `/api/v1/query?query=count(count({__name__!=""}) by (__name__))`, // missing tenant value works
			authorizationHeader: "Bearer " + tokens["magicBypassTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "",
				},
				{
					matchingApp: "only_magic_val",
					status:      http.StatusOK,
					body:        "< fake upstream server response >\n",
				},
				{
					matchingApp: "bad_tenant_intolerant",
					status:      http.StatusForbidden,
					body:        `{"status":"error","errorType":"bad_data","error": "no tenant label values matched"}` + "\n",
				},
			},
		},
		{
			baseName:            "strange_query_with_magic_value_bypass_3",
			URL:                 `/api/v1/query?query=count(count({__name__!="",tenant_id="bob"}) by (__name__))`, // without the magic value, tenant is checked
			authorizationHeader: "Bearer " + tokens["twoGroupsTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "",
				},
				{
					matchingApp: "bad_tenant_intolerant",
					status:      http.StatusForbidden,
					body:        `{"status":"error","errorType":"bad_data","error": "no tenant label values matched"}` + "\n",
				},
			},
		},
		{
			baseName:            "invalid_magic_value_bypass",
			URL:                 `/api/v1/query?query=count(count({__name__!="",tenant_id="bob"}) by (__name__))`, // without the magic value, tenant is checked
			authorizationHeader: "Bearer " + tokens["invalidMagicBypassTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusForbidden,
					body:        "no tenant labels are configured for the user",
				},
			},
		},
		{
			baseName:            "invalid_magic_value_bypass_with_magic_header",
			URL:                 `/api/v1/query?query=count(count({__name__!="",tenant_id="bob"}) by (__name__))`, // without the magic value, tenant is checked
			authorizationHeader: "Bearer " + tokens["invalidMagicBypassTenant"],
			header:              TestHeader{key: "MAGICHEADER", val: "notaverygoodsecret"},
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusForbidden,
					body:        "no tenant labels are configured for the user",
				},
				{
					matchingApp: "only_magic_val",
					status:      http.StatusOK,
					body:        "< fake upstream server response >\n",
				},
			},
		},
		{
			baseName:            "loki_queryrange_with_valid_label",
			URL:                 "/loki/api/v1/query_range?direction=backward&end=1690463973787000000&limit=1000&query=sum by (level) (count_over_time({tenant_id=\"tenant_id_g1\"} |= `path` |= `label` | json | line_format `{{.message}}` | json | line_format `{{.request}}` | json | line_format `{{.method | printf \"%-4s\"}} {{.path | printf \"%-60s\"}} {{.url | urldecode}}`[1m]))&start=1690377573787000000&step=60000ms",
			authorizationHeader: "Bearer " + tokens["twoGroupsTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "",
				},
			},
		},
		{
			baseName:            "loki_index_stats_with_valid_label",
			URL:                 `/loki/api/v1/index/stats?query={tenant_id="tenant_id_u1"}&start=1690377573724000000&end=1690463973724000000`,
			authorizationHeader: "Bearer " + tokens["userTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "",
				},
			},
		},
		{
			baseName:            "loki_big_query_invalid_label_1",
			URL:                 "/loki/api/v1/query_range?direction=backward&end=1690463973693000000&limit=10&query={tenant_id=\"forbidden_tenant\"} |= `path` |= `label` | json | line_format `{{.message}}` | json | line_format `{{.request}}` | json | line_format `{{.method}} {{.path}} {{.url | urldecode}}`&start=1690377573693000000&step=86400000ms",
			authorizationHeader: "Bearer " + tokens["userAndGroupTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "",
				},
				{
					matchingApp: "bad_tenant_intolerant",
					status:      http.StatusForbidden,
					body:        "unauthorized tenant label value",
				},
			},
		},
		{
			baseName:            "loki_big_query_invalid_label_2",
			URL:                 `/loki/api/v1/query_range?direction=backward&end=1690463973693000000&limit=10&query={tenant_id="forbidden_tenant"}`,
			authorizationHeader: "Bearer " + tokens["userTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "",
				},
				{
					matchingApp: "bad_tenant_intolerant",
					status:      http.StatusForbidden,
					body:        "unauthorized tenant label value",
				},
			},
		},
		{
			baseName:            "loki_big_query_invalid_label_3",
			URL:                 `/loki/api/v1/query_range?direction=backward&end=1690463973693000000&limit=10&query={tenant_id="forbidden_tenant"}`,
			authorizationHeader: "Bearer " + tokens["magicBypassTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "",
				},
				{
					matchingApp: "only_magic_val",
					status:      http.StatusOK,
					body:        "< fake upstream server response >\n",
				},
				{
					matchingApp: "bad_tenant_intolerant",
					status:      http.StatusForbidden,
					body:        "unauthorized tenant label value",
				},
			},
		},
	}

	for appname, app := range appmap {
		for _, tc := range cases {
			tc.name = tc.baseName + "/" + appname
			t.Run(tc.name, func(t *testing.T) {

				// Create a request
				log.Debug().Str("URL", tc.URL).Str("Authorization", tc.authorizationHeader).Msg("Request")
				req, err := http.NewRequest("GET", tc.URL, nil)
				if err != nil {
					t.Fatal(err)
				}
				// Set headers based on the test case.
				if !tc.noSetAuthorization {
					req.Header.Add("Authorization", tc.authorizationHeader)
				}

				// Prepare the response recorder
				rr := httptest.NewRecorder()

				// Call the function
				app.e.ServeHTTP(rr, req)

				// Find which of the expected results applies to our situation
				expectedResults := ExpectedResult{}
				for _, maybe := range tc.expectedResults {
					if maybe.matchingApp == appname {
						expectedResults = maybe
					}
				}
				if expectedResults.matchingApp == "" {
					for _, maybe := range tc.expectedResults {
						if maybe.matchingApp == "*" {
							expectedResults = maybe
						}
					}
				}
				if expectedResults.matchingApp == "" {
					log.Warn().Msg("We have apparently not found what results are expected for this test.")
				}

				// Check the status code
				happy := assert.Equal(t, expectedResults.status, rr.Code)

				// Check the response body
				if expectedResults.body != "" {
					happy = happy && assert.Contains(t, rr.Body.String(), expectedResults.body)
				}

				log.Info().Bool("passed", happy).Str("name", tc.name).Str("appname", appname).Msg("Reverse proxy test")
			})
		}
	}
}

func TestIsAdminSkip(t *testing.T) {
	a := assert.New(t)

	app := &App{}
	app.WithConfig()
	app.Cfg.Admin.GroupBypass = true
	app.Cfg.Admin.Group = "gepardec-run-admins"

	token := &OAuthToken{Groups: []string{"gepardec-run-admins"}}
	a.True(isAdmin(*token, app))
	app.Cfg.Admin.GroupBypass = false // show that we need group bypass to be enabled
	a.False(isAdmin(*token, app))

	app.Cfg.Admin.GroupBypass = true
	token.Groups = []string{"usergroup"} // not admin group
	a.False(isAdmin(*token, app))
	app.Cfg.Admin.GroupBypass = false
	a.False(isAdmin(*token, app))

	app.Cfg.Admin.GroupBypass = true
	token.Groups = []string{"gepardec-run-admins", "g2", "g3"}
	a.True(isAdmin(*token, app))
}

func TestLogAndWriteError(t *testing.T) {
	a := assert.New(t)

	rw := httptest.NewRecorder()
	logAndWriteError(rw, http.StatusInternalServerError, nil, "test error")
	a.Equal(http.StatusInternalServerError, rw.Code)
	a.Equal("test error\n", rw.Body.String())
}
