package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
)

// logEverythingElseHandler implements the http.Handler interface, so we can use it to observe HTTP requests.
// Registering something (this handler) for the / path triggered the loggingMiddleware to log these requests.
// When only the "business" routes where registered, requests to invalid paths were invisible in the logs and therefore hard to understand.
type logEverythingElseHandler struct{}

func (h logEverythingElseHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("not a registered route\n")) // this distinctive text at least allows us to know we hit this handler (there is a test case)
}

type requestData struct {
	Method string      `json:"method"`
	URL    string      `json:"url"`
	Header http.Header `json:"header"`
	Body   string      `json:"body"`
}

// loggingMiddleware returns a middleware that logs details of incoming HTTP requests and passes control to the next HTTP handler in the chain.
// If configuration allows for logging tokens, the request body is read and logged.
// Otherwise, the body content is redacted.
func (a *App) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var bodyBytes []byte
		if a.Cfg.Log.LogTokens {
			bodyBytes = readBody(r)
		} else {
			bodyBytes = []byte("[REDACTED]")
		}
		logRequestData(r, bodyBytes, a.Cfg.Log.LogTokens)
		next.ServeHTTP(w, r)

		// crude request logging
		// at this point r.Response == nil so we can't ask about the result with this approach
		log.Info().Str("request URI", r.RequestURI).Str("request method", r.Method).Int64("content length", r.ContentLength).Msg("Request complete")
	})
}

// readBody reads and returns the entire request body.
// If an error occurs during reading, it logs the error and returns nil.
// Note that this function also resets the request's Body to ensure it can be read again by subsequent handlers.
func readBody(r *http.Request) []byte {
	var bodyBytes []byte
	var err error
	if r.Body != nil {
		bodyBytes, err = io.ReadAll(r.Body)
		if err != nil {
			log.Error().Err(err).Msg("")
			return nil
		}
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}
	return bodyBytes
}

// logRequestData logs the specified request's details, including method, headers, and optionally, body content.
// If logToken is false, sensitive headers are cleaned before logging.
// If the request data cannot be marshaled to JSON, an error is logged.
func logRequestData(r *http.Request, bodyBytes []byte, logToken bool) {
	rd := requestData{r.Method, r.URL.String(), r.Header, string(bodyBytes)}
	if logToken {
		rd.Header = cleanSensitiveHeaders(rd.Header)
	}
	jsonData, err := json.Marshal(rd)
	if err != nil {
		log.Error().Err(err).Msg("Error while marshalling request")
		return
	}

	log.Trace().Str("request", string(jsonData)).Msg("") // logs the headers
}

// cleanSensitiveHeaders creates and returns a copy of the provided HTTP headers with sensitive headers removed.
// Sensitive headers like "Authorization", "X-Plugin-Id", and "X-Id-Token" are deleted to prevent them from being logged.
func cleanSensitiveHeaders(headers http.Header) http.Header {
	copyHeader := make(http.Header)
	for k, v := range headers {
		copyHeader[k] = v
	}
	copyHeader.Del("Authorization") // note to self: doesn't actually seem to strip the headers
	copyHeader.Del("X-Plugin-Id")
	copyHeader.Del("X-Id-Token")
	return copyHeader
}

// logAndWriteError logs the provided error and message at the Trace level and writes them to the ResponseWriter along with the specified status code.
// If the message is an empty string, the error's message is written instead.
func logAndWriteError(rw http.ResponseWriter, statusCode int, err error, message string) {
	if message == "" {
		message = fmt.Sprint(err)
	}
	log.Trace().Err(err).Msg(message)
	rw.WriteHeader(statusCode)
	_, _ = fmt.Fprint(rw, message+"\n")
}
