package main

import (
	"testing"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

func TestLogqlEnforcer(t *testing.T) {
	tests := []struct {
		name           string
		query          string
		tenantLabels   []string
		expectedResult string
		expectErr      bool
	}{
		{
			name:           "Valid query and tenant labels",
			query:          "{kubernetes_namespace_name=\"test\"}",
			tenantLabels:   []string{"test"},
			expectedResult: "{kubernetes_namespace_name=\"test\"}",
			expectErr:      false,
		},
		{
			name:           "Empty query and valid tenant labels",
			query:          "",
			tenantLabels:   []string{"test"},
			expectedResult: "{kubernetes_namespace_name=\"test\"}",
			expectErr:      false,
		},
		{
			name:         "Valid query and invalid tenant labels",
			query:        "{kubernetes_namespace_name=\"test\"}",
			tenantLabels: []string{"invalid"},
			expectErr:    true,
		},
	}

	enforcer := LogQLEnforcer{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log.Debug().Str("name", tt.name).Msg("LogQL enforcer test")
			result, err := enforcer.Enforce(tt.query, tt.tenantLabels, "kubernetes_namespace_name", false)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResult, result)
			}
		})
	}
}

func TestMatchNamespaceMatchers(t *testing.T) {
	tests := []struct {
		name         string
		matchers     []*labels.Matcher
		tenantLabels []string
		expectErr    bool
	}{
		{
			name: "Valid matchers and tenant labels",
			matchers: []*labels.Matcher{
				{
					Type:  labels.MatchEqual,
					Name:  "kubernetes_namespace_name",
					Value: "test",
				},
			},
			tenantLabels: []string{"test"},
			expectErr:    false,
		},
		{
			name: "Invalid matchers and valid tenant labels",
			matchers: []*labels.Matcher{
				{
					Type:  labels.MatchEqual,
					Name:  "kubernetes_namespace_name",
					Value: "invalid",
				},
			},
			tenantLabels: []string{"test"},
			expectErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log.Debug().Str("name", tt.name).Msg("LogQL enforcer test")
			_, err := matchNamespaceMatchers(tt.matchers, tt.tenantLabels, "kubernetes_namespace_name")
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
