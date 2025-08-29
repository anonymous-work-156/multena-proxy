package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/http/pprof"
	"net/url"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Route struct {
	Url       string
	MatchWord string
}

// WithHealthz sets up and adds health check endpoints (/healthz and /debug/pprof/)
// and metrics endpoint (/metrics) to a new router
func (a *App) WithHealthz() *App {
	i := mux.NewRouter()
	a.healthy = true
	i.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if a.healthy {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Ok"))
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Not Ok"))
		}
	})
	i.HandleFunc("/debug/pprof/", pprof.Index)
	i.Handle("/metrics", promhttp.Handler())
	a.i = i
	return a
}

// WithRoutes initializes a new router, sets up logging middleware, and assigns
// the router to the App's router field, returning the updated App.
func (a *App) WithRoutes() *App {
	e := mux.NewRouter()
	e.Use(a.loggingMiddleware)
	e.SkipClean(true)
	a.e = e
	a.WithLoki()
	a.WithThanos()
	e.PathPrefix("/").Handler(logEverythingElseHandler{}) // hackish way to help all requests get logged
	return a
}

// WithLoki configures and adds a set of Loki API routes to the App's router,
// logging warnings if the Loki URL is not set, and returns the updated App.
func (a *App) WithLoki() *App {
	if a.Cfg.Loki.URL == "" {
		log.Warn().Msg("Loki URL not set, skipping Loki routes")
		return a
	}
	routes := []Route{
		{Url: "/api/v1/query", MatchWord: "query"},
		{Url: "/api/v1/query_range", MatchWord: "query"},
		{Url: "/api/v1/series", MatchWord: "match[]"},
		{Url: "/api/v1/tail", MatchWord: "query"},
		{Url: "/api/v1/index/stats", MatchWord: "query"},
		{Url: "/api/v1/format_query", MatchWord: "query"},
		{Url: "/api/v1/labels", MatchWord: "query"},
		{Url: "/api/v1/label/{label}/values", MatchWord: "query"},
		{Url: "/api/v1/query_exemplars", MatchWord: "query"},
		{Url: "/api/v1/status/buildinfo", MatchWord: "query"},
	}
	lokiRouter := a.e.PathPrefix(a.Cfg.Loki.PathPrefix).Subrouter()
	for _, route := range routes {
		log.Trace().Any("route", route).Msg("Loki route")
		lokiRouter.HandleFunc(route.Url,
			handler(route.MatchWord,
				LogQLEnforcer(struct{}{}),
				a.Cfg.Loki.URL,
				a.Cfg.Loki.UseMutualTLS,
				a.Cfg.Loki.Headers,
				a)).Name(route.Url)
	}
	return a
}

// WithThanos configures and adds a set of Thanos API routes to the App's router,
// logging warnings if the Thanos URL is not set, and returns the updated App.
func (a *App) WithThanos() *App {
	if a.Cfg.Thanos.URL == "" {
		log.Warn().Msg("Thanos URL not set, skipping Thanos routes")
		return a
	}
	routes := []Route{
		{Url: "/api/v1/query", MatchWord: "query"},
		{Url: "/api/v1/query_range", MatchWord: "query"},
		{Url: "/api/v1/series", MatchWord: "match[]"},
		{Url: "/api/v1/tail", MatchWord: "query"},
		{Url: "/api/v1/index/stats", MatchWord: "query"},
		{Url: "/api/v1/format_query", MatchWord: "query"},
		{Url: "/api/v1/labels", MatchWord: "match[]"},
		{Url: "/api/v1/label/{label}/values", MatchWord: "match[]"},
		{Url: "/api/v1/query_exemplars", MatchWord: "query"},
		{Url: "/api/v1/status/buildinfo", MatchWord: "query"},
		{Url: "/api/v1/rules", MatchWord: ""},
		{Url: "/api/v1/alerts", MatchWord: ""},
	}
	thanosRouter := a.e.PathPrefix(a.Cfg.Thanos.PathPrefix).Subrouter()
	for _, route := range routes {
		log.Trace().Any("route", route).Msg("Thanos route")
		thanosRouter.HandleFunc(route.Url,
			handler(route.MatchWord,
				PromQLEnforcer(struct{}{}),
				a.Cfg.Thanos.URL,
				a.Cfg.Thanos.UseMutualTLS,
				a.Cfg.Thanos.Headers,
				a)).Name(route.Url)
	}
	return a
}

// handler function orchestrates the request flow through the proxy, comprising
// authentication, conditional enforcement, and forwarding to the upstream server.
//
// There are a variety of ways that tenant label value enforcement can be skipped.
// If enforcement is not skipped, user and group membership will be fetched from either a header or OAuth token.
//
// Subsequently, user and group information will be checked against the values in the label store.
// If enforcement is still not skipped, label values which are appropriate for the user and group will be enforced.
// Should any enforcement error arise, it is logged and a forbidden status is sent to the client.
//
// Finally, if all checks and possible enforcement pass successfully, the request is streamed to the upstream server.
func handler(matchWord string, enforcer EnforceQL, dsURL string, tls bool, headers map[string]string, a *App) func(http.ResponseWriter, *http.Request) {
	upstreamURL, err := url.Parse(dsURL)
	if err != nil {
		log.Fatal().Err(err).Str("url", dsURL).Msg("Error parsing URL")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		doTheProxy := innerHandler(matchWord, enforcer, w, r, a)
		if doTheProxy {
			log.Trace().Any("r", r.URL).Any("r.ContentLength", r.ContentLength).Any("r.URL.RawQuery", r.URL.RawQuery).Msg("")
			streamUp(w, r, upstreamURL, tls, headers, a)
		}
	}
}

func innerHandler(matchWord string, enforcer EnforceQL, w http.ResponseWriter, r *http.Request, a *App) bool {
	skip := checkBypassHeader(r, a)
	if skip {
		log.Debug().Msg("No label enforcement (due to bypass header).")
		r.URL.RawQuery = r.URL.Query().Encode() // currently a mystery as to why URL escaping isn't magical
		return true
	}

	var labels []string

	groups := checkGroupHeader(r, a)
	if len(groups) > 0 {
		labels, skip = a.LabelStore.GetLabels(OAuthToken{Groups: groups}, a)
	} else {
		oauthToken, err := getToken(r, a)
		if err != nil {
			logAndWriteError(w, http.StatusForbidden, err, "")
			return false
		}

		labels, skip, err = validateLabels(oauthToken, a)
		if err != nil {
			logAndWriteError(w, http.StatusForbidden, err, "")
			return false
		}
	}

	if skip || matchWord == "" {
		log.Debug().Msg("No label enforcement.")
		r.URL.RawQuery = r.URL.Query().Encode() // currently a mystery as to why URL escaping isn't magical
	} else {
		err := enforceRequest(r, enforcer, labels, matchWord, a.Cfg)
		if err != nil {
			logAndWriteError(w, http.StatusForbidden, err, "")
			return false
		}
	}

	return true
}

// checkBypassAndGroupHeaders checks to see if the request contains a header that changes how we do enforcement.
// There is an optional header which skips all enforcement, and an optional header which defines group membership.
func checkBypassHeader(r *http.Request, app *App) bool {

	// check for bypassing enforcement via header
	if app.Cfg.Admin.HeaderBypass.Enabled && app.Cfg.Admin.HeaderBypass.Key != "" && app.Cfg.Admin.HeaderBypass.Value != "" {
		if r.Header.Get(app.Cfg.Admin.HeaderBypass.Key) == app.Cfg.Admin.HeaderBypass.Value {
			log.Debug().Msg("Header indicates that we can skip enforcement.")
			return true
		}
		log.Debug().Msg("Header-based bypass is enabled, but skipped.")
	} else {
		log.Debug().Msg("Header-based bypass is not enabled.")
	}

	return false
}

// checkBypassAndGroupHeaders checks to see if the request contains a header that changes how we do enforcement.
// There is an optional header which skips all enforcement, and an optional header which defines group membership.
func checkGroupHeader(r *http.Request, app *App) []string {

	// check for group membership via header (can also bypass enforcement)
	if app.Cfg.Web.HeaderToDefineGroups.Enabled && app.Cfg.Web.HeaderToDefineGroups.Name != "" && app.HeaderToDefineGroupsEncryptionKey != "" {
		val := r.Header.Get(app.Cfg.Web.HeaderToDefineGroups.Name)
		if val != "" {
			groups, err := decryptGroupHeader(val, app.HeaderToDefineGroupsEncryptionKey)
			if err != nil {
				log.Debug().Msg("Failed to interpret groups header.")
				return nil
			}
			return groups
		}
	} else {
		log.Debug().Msg("Header-based group membership is not enabled.")
	}

	log.Debug().Msg("Header (or lack thereof) indicates that we can not skip enforcement.")
	return nil
}

// decryptGroupHeader decrypts base64-encoded header payload with a base64-encoded 32-byte key
func decryptGroupHeader(base64HeaderPayload string, base64Key string) ([]string, error) {
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(base64HeaderPayload)
	if err != nil {
		return nil, err
	}

	// create cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// extract nonce
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// decrypt payload
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return strings.Split(string(plaintext), ","), nil
}

// streamUp forwards the provided HTTP request to the specified upstream URL using a reverse proxy.
// It serves the upstream content back to the original client.
func streamUp(w http.ResponseWriter, r *http.Request, upstreamURL *url.URL, tls bool, headers map[string]string, a *App) {
	setHeaders(r, tls, headers, a.ServiceAccountToken)
	proxy := httputil.NewSingleHostReverseProxy(upstreamURL)

	// log the result code
	proxy.ModifyResponse = func(res *http.Response) error {
		log.Info().Any("Result status code from proxied server", res.StatusCode).Msg("")
		return nil
	}

	proxy.ServeHTTP(w, r)
}

// setHeaders modifies the HTTP request headers to set the Authorization and
// other headers based on the provided arguments.
func setHeaders(r *http.Request, tls bool, header map[string]string, sat string) {
	if !tls {
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sat))
	}
	for k, v := range header {
		r.Header.Set(k, v)
	}
}
