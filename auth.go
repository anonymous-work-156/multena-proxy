package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"

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
	authToken, err := trimBearerToken(r, a.Cfg.Web.HeaderContainingJWT)
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
func trimBearerToken(r *http.Request, header_name string) (string, error) {
	authToken := r.Header.Get(header_name)
	if authToken == "" {
		return "", fmt.Errorf("got no value for the HTTP header which is expected to contain the JWT")
	}
	if header_name == "Authorization" {
		splitToken := strings.Split(authToken, "Bearer")
		if len(splitToken) != 2 {
			return "", fmt.Errorf("failed to remove the bearer prefix from the JWT")
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

	// usernames can optionally be pointed at approved tenant label values in the configuration
	if v, ok := claimsMap["preferred_username"].(string); ok {
		log.Debug().Str("username", v).Msg("Found value for preferred_username in token")
		oAuthToken.PreferredUsername = v
	} else {
		log.Warn().Msg("Failed to find value for preferred_username in token")
	}

	// we don't actually use the email for anything currently, but it could be treated like a username
	if v, ok := claimsMap["email"].(string); ok {
		log.Debug().Str("email", v).Msg("Found value for email in token")
		oAuthToken.Email = v
	}

	// groups can optionally be pointed at approved tenant label values in the configuraion
	if v, ok := claimsMap[a.Cfg.Web.OAuthGroupName].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				oAuthToken.Groups = append(oAuthToken.Groups, s)
			}
		}
		log.Debug().Str("groups", strings.Join(oAuthToken.Groups, ",")).Msg("Found value for group in token")
	} else {
		log.Warn().Msg("Failed to find value for group in token")
	}
	return oAuthToken, token, nil
}

// validateLabels validates the labels in the OAuth token.
// It checks if the user is an admin and skips label enforcement if true.
// Returns a list of valid values for the tenant label, a boolean indicating whether label enforcement should be skipped,
// and any error that occurred during validation.
func validateLabels(token OAuthToken, a *App) ([]string, bool, error) {
	if isAdmin(token, a) {
		log.Debug().Str("user", token.PreferredUsername).Bool("Admin", true).Msg("Skipping label enforcement")
		return nil, true, nil
	}

	tenantLabels, skip := a.LabelStore.GetLabels(token, a)
	if skip {
		log.Debug().Str("user", token.PreferredUsername).Bool("Admin", false).Msg("Skipping label enforcement")
		return nil, true, nil
	}
	log.Debug().Str("user", token.PreferredUsername).Strs("labels", tenantLabels).Msg("")

	if len(tenantLabels) < 1 {
		return nil, false, fmt.Errorf("no tenant labels are configured for the user") // FIXME: this error is badly formatted, and sometimes unhelpful
	}
	return tenantLabels, false, nil
}

func isAdmin(token OAuthToken, a *App) bool {
	return ContainsIgnoreCase(token.Groups, a.Cfg.Admin.Group) && a.Cfg.Admin.GroupBypass
}
