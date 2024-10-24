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
		expected []string
		skip     bool
	}{
		{
			name:     "User with groups",
			username: "user1",
			groups:   []string{"group1", "group2"},
			expected: []string{"u1", "u2", "g1", "g2", "g3", "g4"},
		},
		{
			name:     "User without groups",
			username: "user2",
			groups:   []string{},
			expected: []string{"u3", "u4"},
		},
		{
			name:     "Non-existent user",
			username: "user3",
			groups:   []string{"group1"},
			expected: []string{"g1", "g2"},
		},
		{
			name:     "Non-existent group",
			username: "user1",
			groups:   []string{"group3"},
			expected: []string{"u1", "u2"},
		},
		{
			name:     "admin_group",
			username: "blubb",
			groups:   []string{"adminGroup"},
			expected: nil,
			skip:     true,
		},
	}

	app := &App{}
	app.WithConfig()
	app.Cfg.Admin.GroupBypass = false
	app.Cfg.Admin.MagicValueBypass = true
	app.Cfg.Admin.MagicValue = "#cluster-wide"

	for _, tc := range cases {

		t.Run(tc.name, func(t *testing.T) {
			labels, skip := cmh.GetLabels(OAuthToken{PreferredUsername: tc.username, Groups: tc.groups}, app)
			happy := assert.ElementsMatch(t, tc.expected, labels)
			happy = happy && assert.Equal(t, tc.skip, skip)

			log.Info().Bool("passed", happy).Str("name", tc.name).Msg("Labelstore test")
		})
	}
}
