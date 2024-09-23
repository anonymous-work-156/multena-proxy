package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
	"golang.org/x/exp/maps"

	"github.com/golang-jwt/jwt/v5"
)

// OAuthToken represents the structure of an OAuth token.
// It holds user-related information extracted from the token.
type OAuthToken struct {
	Groups            []string `json:"-"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	jwt.RegisteredClaims
}

// getToken retrieves the OAuth token from the incoming HTTP request.
// It extracts, parses, and validates the token from the Authorization header.
func getToken(r *http.Request, a *App) (OAuthToken, error) {
	authToken, err := trimBearerToken(r)
	if err != nil {
		return OAuthToken{}, err
	}
	oauthToken, token, err := parseJwtToken(authToken, a)
	if err != nil {
		return OAuthToken{}, fmt.Errorf("error parsing token")
	}
	if !token.Valid {
		return OAuthToken{}, fmt.Errorf("invalid token")
	}
	return oauthToken, nil
}

// trimBearerToken extracts the token from the Authorization header of the HTTP request.
// It trims the "Bearer" prefix from the Authorization header and returns the actual token.
func trimBearerToken(r *http.Request) (string, error) {
	authToken := r.Header.Get("Authorization") // here HeaderContainingJWT
	if authToken == "" {
		return "", errors.New("got no value for the HTTP header which is expected to contain the JWT")
	}
	if strings.HasPrefix(authToken, "Bearer ") {
		// we can probably not care about the formality around "Bearer" existing or not, we just want a JWT
		splitToken := strings.Split(authToken, "Bearer")
		if len(splitToken) != 2 {
			return "", errors.New("failed to remove the bearer prefix from the JWT")
		}
		return strings.TrimSpace(splitToken[1]), nil
	}
	return authToken, nil
}

// parseJwtToken parses the JWT token string and constructs an OAuthToken from the parsed claims.
// It returns the constructed OAuthToken, the parsed jwt.Token, and any error that occurred during parsing.
func parseJwtToken(tokenString string, a *App) (OAuthToken, *jwt.Token, error) {
	var oAuthToken OAuthToken
	var claimsMap jwt.MapClaims

	token, err := jwt.ParseWithClaims(tokenString, &claimsMap, a.Jwks.Keyfunc)
	if err != nil {
		return oAuthToken, nil, err
	}

	if v, ok := claimsMap["preferred_username"].(string); ok {
		log.Debug().Msg("Found value for preferred_username in token")
		oAuthToken.PreferredUsername = v
	} else {
		log.Warn().Msg("Failed to find value for preferred_username in token")
	}
	if v, ok := claimsMap["email"].(string); ok {
		oAuthToken.Email = v
	}

	if v, ok := claimsMap[a.Cfg.Web.OAuthGroupName].([]interface{}); ok {
		log.Debug().Msg("Found value for group in token")
		for _, item := range v {
			if s, ok := item.(string); ok {
				oAuthToken.Groups = append(oAuthToken.Groups, s)
			}
		}
	} else {
		log.Warn().Msg("Failed to find value for group in token")
	}
	return oAuthToken, token, err
}

// validateLabels validates the labels in the OAuth token.
// It checks if the user is an admin and skips label enforcement if true.
// Returns a map representing valid labels, a boolean indicating whether label enforcement should be skipped,
// and any error that occurred during validation.
func validateLabels(token OAuthToken, a *App) (map[string]bool, bool, error) {
	if isAdmin(token, a) {
		log.Debug().Str("user", token.PreferredUsername).Bool("Admin", true).Msg("Skipping label enforcement")
		return nil, true, nil
	}

	tenantLabels, skip := a.LabelStore.GetLabels(token)
	if skip {
		log.Debug().Str("user", token.PreferredUsername).Bool("Admin", false).Msg("Skipping label enforcement")
		return nil, true, nil
	}
	log.Debug().Str("user", token.PreferredUsername).Strs("labels", maps.Keys(tenantLabels)).Msg("")

	if len(tenantLabels) < 1 {
		return nil, false, fmt.Errorf("no tenant labels found")
	}
	return tenantLabels, false, nil
}

func isAdmin(token OAuthToken, a *App) bool {
	return ContainsIgnoreCase(token.Groups, a.Cfg.Admin.Group) && a.Cfg.Admin.Bypass
}
