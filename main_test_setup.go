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
	"net/url"
	"regexp"
	"sort"
	"strings"

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

func makeTestApp(jwksServer, upstreamServer *httptest.Server, cmh *ConfigMapHandler, errorOnIllegalTenantValue bool, adminGroup bool, magicValueBypass bool, headerBypass bool, groupsHeader bool) App {
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
		app.Cfg.Admin.Group = "magic-admin-in-config" // magic-admin-in-config matches tenant defined in setupReverseProxyTest()
	}

	app.Cfg.Admin.MagicValueBypass = magicValueBypass
	if magicValueBypass {
		app.Cfg.Admin.MagicValue = "#cluster-wide" // #cluster-wide is associated with a user in ConfigMapHandler
	}

	app.Cfg.Admin.HeaderBypass.Enabled = headerBypass
	if headerBypass {
		app.Cfg.Admin.HeaderBypass.Key = "MagicHeader"
		app.Cfg.Admin.HeaderBypass.Value = "notaverygoodsecret"
	}

	app.Cfg.Web.GroupFromHeader.Enabled = groupsHeader
	if groupsHeader {
		app.Cfg.Web.GroupFromHeader.Name = "GroupHeader"
	}

	app.LabelStore = cmh
	app.WithRoutes()

	return app
}

func makeDummyServer() func(http.ResponseWriter, *http.Request) {
	re1, err := regexp.Compile(`^(/[\w.-]+)+\w+$`)
	if err != nil {
		panic(fmt.Sprintf("Failed to compile regex: %s\n", err))
	}

	re2, err := regexp.Compile(`^(/[\w.-]+)+\w([?&]\w+=[\w.%~+-]+)+$`)
	if err != nil {
		panic(fmt.Sprintf("Failed to compile regex: %s\n", err))
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if !(re1.MatchString(r.RequestURI) || re2.MatchString(r.RequestURI)) {
			log.Info().Any("Fake metrics/logs server RequestURI", r.RequestURI).Msg("Fake metrics/logs server sending HTTP 400 response.")
			w.WriteHeader(http.StatusBadRequest)
			_, err := fmt.Fprint(w, "Bad Parameters")
			if err != nil {
				log.Error().Msg("Some kind of error in the fake metrics/logs server while writing an error.")
			}
			return
		}

		values, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			log.Error().Err(err).Msg("Fake metrics/logs server failed to parse the URL.")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		keys := make([]string, 0, len(values))
		for k := range values {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		log.Info().Any("RequestURI", r.RequestURI).Msg("Fake metrics/logs server sending HTTP 200 response.")
		w.WriteHeader(http.StatusOK)
		if len(keys) == 0 {
			_, err = fmt.Fprintln(w, "Query string did not contain parameters.")
		} else {
			_, err = fmt.Fprintln(w, "Query string parameter keys: "+strings.Join(keys, ","))
		}
		if err != nil {
			log.Error().Msg("Some kind of error in the fake metrics/logs server.")
		}
	}
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
			Username: "user-not-in-config",
			Email:    "not.used@for.anything",
			Groups:   []string{},
		},
		{
			name:     "invalidTenantWithGroups",
			Username: "user-not-in-config",
			Email:    "not.used@for.anything",
			Groups:   []string{"invalid-group1", "invalid-group2"},
		},
		{
			name:     "userTenant",
			Username: "user-in-config", // defined as a valid user in ConfigMapHandler
			Email:    "not.used@for.anything",
			Groups:   []string{},
		},
		{
			name:     "groupTenant",
			Username: "user-not-in-config",
			Email:    "not.used@for.anything",
			Groups:   []string{"group1"}, // defined as a valid group in CM in ConfigMapHandler
		},
		{
			name:     "twoGroupsTenant",
			Username: "user-not-in-config",
			Email:    "not.used@for.anything",
			Groups:   []string{"group1", "group2"}, // defined as two valid groups in CM in ConfigMapHandler
		},
		{
			name:     "userAndGroupTenant",
			Username: "user-in-config", // defined as a valid user in CM in ConfigMapHandler
			Email:    "not.used@for.anything",
			Groups:   []string{"group1", "group2"}, // defined as two valid groups in CM in ConfigMapHandler
		},
		{
			name:     "adminBypassTenant",
			Username: "adminuser-not-in-config",
			Email:    "not.used@for.anything",
			Groups:   []string{"magic-admin-in-config", "group-not-defined", "group-also-not-defined"}, // magic-admin-in-config matches group set in main config
		},
		{
			name:     "nestedBypassTenant",
			Username: "adminuser-not-in-config",
			Email:    "not.used@for.anything",
			Groups:   []string{"admin-in-config", "group-not-defined", "group-also-not-defined"}, // admin-in-config matches group set in nested ConfigMapHandler
		},
		{
			name:     "magicBypassTenant",
			Username: "bypass-admin-in-config", // defined as a valid user in CM in ConfigMapHandler with magic value access
			Email:    "not.used@for.anything",
			Groups:   []string{"whatever", "something"}, // these groups are not assigned to label values in ConfigMapHandler, therefore unusable
		},
		{
			name:     "invalidMagicBypassTenant",
			Username: "user-not-in-config",
			Email:    "not.used@for.anything",
			Groups:   []string{"#cluster-wide"}, // #cluster-wide matches value set in makeTestApp() but not in a useful way
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
	jwksServer := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				log.Info().Msg("Fake JWKS server sending response.")
				_, err := fmt.Fprintf(w, `{"keys":[{"kty":"EC","kid":"testKid","alg":"ES256","use":"sig","x":"%s","y":"%s","crv":"P-256"}]}`, x, y)
				if err != nil {
					log.Error().Msg("Some kind of error in the fake JWKS server.")
					return // we are in a test server, do nothing with the error
				}
			},
		),
	)

	// Set up the upstream server
	upstreamServer := httptest.NewServer(http.HandlerFunc(makeDummyServer()))
	log.Debug().Str("Test server upstreamServer.URL", upstreamServer.URL).Msg("")

	// this is our config defining what tenant label values are valid for the test cases
	// the tenant label name is set above (to "tenant_id")
	cmh_linear := ConfigMapHandler{
		labels: map[string]map[string]bool{
			"user-in-config":         {"tenant_id_u1": true, "tenant_id_u2": true},
			"bypass-admin-in-config": {"tenant_id_u1": true, "tenant_id_u2": true, "#cluster-wide": true},
			"group1":                 {"tenant_id_g1": true, "tenant_id_g2": true},
			"group2":                 {"tenant_id_g3": true, "tenant_id_g4": true},
		},
	}
	cmh_nested := ConfigMapHandler{
		nestedLabels: &NestedLabelConfig{
			Admins: []string{"admin-in-config"},
			Solutions: []InnerNestedLabelConfig{
				{
					Name:         "user area",
					FilterValues: []string{"tenant_id_u1", "tenant_id_u2"},
					Groups:       []string{"user-in-config"},
				},
				{
					Name:         "group1 area",
					FilterValues: []string{"tenant_id_g1", "tenant_id_g2"},
					Groups:       []string{"group1"},
				},
				{
					Name:         "group2 area",
					FilterValues: []string{"tenant_id_g3", "tenant_id_g4"},
					Groups:       []string{"group2"},
				},
			},
		},
	}

	appmap := map[string]App{
		"bad_tenant_tolerant":        makeTestApp(jwksServer, upstreamServer, &cmh_linear, false, true, false, false, false),
		"bad_tenant_tolerant_nested": makeTestApp(jwksServer, upstreamServer, &cmh_nested, false, true, false, false, false),
		"bad_tenant_intolerant":      makeTestApp(jwksServer, upstreamServer, &cmh_linear, true, true, false, false, false),
		"only_magic_val":             makeTestApp(jwksServer, upstreamServer, &cmh_linear, false, false, true, false, false),
		"group_or_header":            makeTestApp(jwksServer, upstreamServer, &cmh_linear, false, true, false, true, false),
		"group_from_header":          makeTestApp(jwksServer, upstreamServer, &cmh_nested, false, false, false, false, true),
	}
	return appmap, tokens
}
