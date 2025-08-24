package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

// EnforceQL represents an interface that any query language enforcement should implement.
// It contains a method to enforce queries based on tenant labels and label match.
type EnforceQL interface {
	Enforce(query string, allowedTenantLabelValues []string, config *Config) (string, error)
}

// enforceRequest enforces the incoming HTTP request based on its method (GET or POST).
// It delegates the enforcement to enforceGet or enforcePost functions based on the HTTP method of the request.
func enforceRequest(r *http.Request, enforce EnforceQL, allowedTenantLabelValues []string, matchWord string, config *Config) error {
	switch r.Method {
	case http.MethodGet:
		return enforceGet(r, enforce, allowedTenantLabelValues, matchWord, config)
	case http.MethodPost:
		return enforcePost(r, enforce, allowedTenantLabelValues, matchWord, config)
	default:
		return fmt.Errorf("invalid method")
	}
}

// enforceGet enforces the query parameters of the incoming GET HTTP request.
// It modifies the request URL's query parameters to ensure they adhere to tenant labels and label match.
func enforceGet(r *http.Request, enforce EnforceQL, allowedTenantLabelValues []string, matchWord string, config *Config) error {
	log.Trace().Str("kind", "urlmatch").Str("queryMatch", matchWord).Str("query", r.URL.Query().Get("query")).Str("match[]", r.URL.Query().Get("match[]")).Msg("")

	query, err := enforce.Enforce(r.URL.Query().Get(matchWord), allowedTenantLabelValues, config)
	if err != nil {
		return err
	}
	log.Trace().Any("URL", r.URL).Msg("pre-enforced URL")
	values := r.URL.Query()
	values.Set(matchWord, query)
	r.URL.RawQuery = values.Encode()
	log.Trace().Any("URL", r.URL).Msg("post-enforced URL")

	r.Body = io.NopCloser(strings.NewReader(""))
	r.ContentLength = 0
	return nil
}

// enforcePost enforces the form values of the incoming POST HTTP request.
// It modifies the request's form values to ensure they adhere to tenant labels and label match.
func enforcePost(r *http.Request, enforce EnforceQL, allowedTenantLabelValues []string, matchWord string, config *Config) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	log.Trace().Str("kind", "bodymatch").Str("queryMatch", matchWord).Str("query", r.PostForm.Get("query")).Str("match[]", r.PostForm.Get("match[]")).Msg("")

	query := r.PostForm.Get(matchWord)
	query, err := enforce.Enforce(query, allowedTenantLabelValues, config)
	if err != nil {
		return err
	}

	_ = r.Body.Close()
	r.PostForm.Set(matchWord, query)
	newBody := r.PostForm.Encode()
	r.Body = io.NopCloser(strings.NewReader(newBody))
	r.ContentLength = int64(len(newBody))
	r.URL.RawQuery = ""
	return nil
}
