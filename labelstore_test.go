package main

import (
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

func TestGetLabelsCM(t *testing.T) {

	cmh := ConfigMapHandler{
		// config keys that are ingested through the Viper lib will be lower case
		// if we set upper case directly in this test, it will not represent real world
		labels: map[string]map[string]bool{
			"user1":      {"u1": true, "u2": true},
			"user2":      {"u3": true, "u4": true},
			"group1":     {"g1": true, "g2": true},
			"group2":     {"g3": true, "g4": true},
			"admingroup": {"#cluster-wide": true, "g4": true},
		},
	}

	cases := []struct {
		name     string
		username string
		groups   []string
		expected map[string]bool
		skip     bool
	}{
		{
			name:     "User with groups",
			username: "user1",
			groups:   []string{"group1", "group2"},
			expected: map[string]bool{
				"u1": true,
				"u2": true,
				"g1": true,
				"g2": true,
				"g3": true,
				"g4": true,
			},
		},
		{
			name:     "User without groups",
			username: "user2",
			groups:   []string{},
			expected: map[string]bool{
				"u3": true,
				"u4": true,
			},
		},
		{
			name:     "Non-existent user",
			username: "user3",
			groups:   []string{"group1"},
			expected: map[string]bool{
				"g1": true,
				"g2": true,
			},
		},
		{
			name:     "Non-existent group",
			username: "user1",
			groups:   []string{"group3"},
			expected: map[string]bool{
				"u1": true,
				"u2": true,
			},
		},
		{
			name:     "admin_group",
			username: "blubb",
			groups:   []string{"adminGroup"},
			expected: nil,
			skip:     true,
		},
	}

	for _, tc := range cases {

		t.Run(tc.name, func(t *testing.T) {
			labels, skip := cmh.GetLabels(OAuthToken{PreferredUsername: tc.username, Groups: tc.groups})
			happy := assert.Equal(t, tc.expected, labels)
			happy = happy && assert.Equal(t, tc.skip, skip)

			log.Info().Bool("passed", happy).Str("name", tc.name).Msg("Labelstore test")
		})
	}
}
