package main

import (
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

func TestGetLabelsCM(t *testing.T) {

	// linear (original) CM format
	configMapLinear := ConfigMapHandler{
		labels: map[string]map[string]bool{
			"user1":      {"lu1": true, "lu2": true},
			"user2":      {"lu3": true, "lu4": true},
			"group1":     {"lg1": true, "lg2": true},
			"group2":     {"lg2": true, "lg3": true, "lg4": true},
			"adminGroup": {"#cluster-wide": true, "lg4": true},
		},
		nestedLabels: nil,
	}

	// nested (new) CM format
	configMapNested := ConfigMapHandler{
		labels: map[string]map[string]bool{},
		nestedLabels: &NestedLabelConfig{
			Admins: []string{"adminGroup"},
			Solutions: []InnerNestedLabelConfig{
				{
					Name:         "solution 1",
					FilterValues: []string{"lu1", "lu2"},
					Groups:       []string{"user1"},
				},
				{
					Name:         "solution 2",
					FilterValues: []string{"lu3", "lu4"},
					Groups:       []string{"user2"},
				},
				{
					Name:         "solution 3",
					FilterValues: []string{"lg1", "lg2"},
					Groups:       []string{"group1"},
				},
				{
					Name:         "solution 4",
					FilterValues: []string{"lg2", "lg3", "lg4"},
					Groups:       []string{"group2"},
				},
			},
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
			name:     "user_with_groups",
			username: "user1",
			groups:   []string{"group1", "group2"}, // its fine to have multiple groups
			expected: []string{"lu1", "lu2", "lg1", "lg2", "lg3", "lg4"},
		},
		{
			name:     "user_without_groups",
			username: "user2",
			groups:   []string{}, // its fine to have no groups
			expected: []string{"lu3", "lu4"},
		},
		{
			name:     "unknown_user_with_ok_group",
			username: "user3", // nothing wrong with users that are not configured in our CM (but they need a known group)
			groups:   []string{"group1"},
			expected: []string{"lg1", "lg2"},
		},
		{
			name:     "unknown_user_with_ok_group_and_unknown_group",
			username: "user3", // nothing wrong with users that are not configured in our CM (but they need a known group)
			groups:   []string{"group1", "group3"},
			expected: []string{"lg1", "lg2"},
		},
		{
			name:     "unknown_group_with_ok_user",
			username: "user1",
			groups:   []string{"group3"}, // nothing wrong with groups that are not configured in our CM (but they need a known user)
			expected: []string{"lu1", "lu2"},
		},
		{
			name:     "unknown_user_and_group",
			username: "user3",
			groups:   []string{"group3"},
			expected: []string{}, // fine to have unknown users *and* groups, but they get no approved filter values
		},
		{
			name:     "admin_group_alone",
			username: "blubb",
			groups:   []string{"adminGroup"},
			expected: nil,
			skip:     true,
		},
		{
			name:     "admin_group",
			username: "billyjoe",
			groups:   []string{"group1", "adminGroup", "group3"},
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

			// linear (original) CM format
			labels, skip := configMapLinear.GetLabels(OAuthToken{PreferredUsername: tc.username, Groups: tc.groups}, app)
			happy := assert.ElementsMatch(t, tc.expected, labels)
			happy = happy && assert.Equal(t, tc.skip, skip)

			// nested (new) CM format
			labels, skip = configMapNested.GetLabels(OAuthToken{PreferredUsername: tc.username, Groups: tc.groups}, app)
			happy = happy && assert.ElementsMatch(t, tc.expected, labels)
			happy = happy && assert.Equal(t, tc.skip, skip)

			log.Info().Bool("passed", happy).Str("name", tc.name).Msg("Labelstore CM test")
		})
	}
}

func TestGetLabelsLinearCM(t *testing.T) {

	cases := []struct {
		name     string
		username string
		groups   []string
		expected []string
		skip     bool
	}{
		{
			name:     "user_with_complex_name",
			username: "User.With.Email.Format@and_underscores", // caps and funny chars that caused confusion for the viper config system (RIP)
			groups:   []string{},
			expected: []string{"helloworld"},
		},
		{
			name:     "unknown_user_with_ok_group",
			username: "user4", // nothing wrong with users that are not configured in our CM (but they need a known group)
			groups:   []string{"group2"},
			expected: []string{"grafana", "opernshift-logging", "opernshift-monitoring"},
		},
		{
			name:     "unknown_user_with_ok_group_and_unknown_group",
			username: "user4", // nothing wrong with users that are not configured in our CM (but they need a known group)
			groups:   []string{"group2", "group3"},
			expected: []string{"grafana", "opernshift-logging", "opernshift-monitoring"},
		},
		{
			name:     "unknown_group_with_ok_user",
			username: "user1",
			groups:   []string{"group3"}, // nothing wrong with groups that are not configured in our CM (but they need a known user)
			expected: []string{"hogarama"},
		},
		{
			name:     "unknown_user_and_group",
			username: "user4",
			groups:   []string{"group4"},
			expected: []string{}, // fine to have unknown users *and* groups, but they get no approved filter values
		},
		{
			name:     "admin_group",
			username: "blubb",
			groups:   []string{"group1"},
			expected: nil,
			skip:     true,
		},
	}

	app := &App{}
	app.WithConfig()
	app.Cfg.Admin.LabelStoreKind = "configmap"     // this also the default value
	app.Cfg.Admin.LabelStoreFile = "linear-labels" // file we load from disk (minus extension)
	app.Cfg.Admin.GroupBypass = false
	app.Cfg.Admin.MagicValueBypass = true
	app.Cfg.Admin.MagicValue = "#cluster-wide" // needs to match value in the file we load from disk

	// linear (original) CM format
	configMapLinear := ConfigMapHandler{}
	configMapLinear.Connect(*app)

	for _, tc := range cases {

		t.Run(tc.name, func(t *testing.T) {

			// linear (original) CM format
			labels, skip := configMapLinear.GetLabels(OAuthToken{PreferredUsername: tc.username, Groups: tc.groups}, app)
			happy := assert.ElementsMatch(t, tc.expected, labels)
			happy = happy && assert.Equal(t, tc.skip, skip)

			log.Info().Bool("passed", happy).Str("name", tc.name).Msg("Labelstore linear CM test")
		})
	}
}

func TestGetLabelsNestedCM(t *testing.T) {

	cases := []struct {
		name     string
		username string
		groups   []string
		expected []string
		skip     bool
	}{
		{
			name:     "unknown_user_with_ok_group",
			username: "user4", // nothing wrong with users that are not configured in our CM (but they need a known group)
			groups:   []string{"group1"},
			expected: []string{"val1", "val2", "val3", "val4"},
		},
		{
			name:     "unknown_user_with_ok_group_and_unknown_group",
			username: "user4", // nothing wrong with users that are not configured in our CM (but they need a known group)
			groups:   []string{"group3", "group4"},
			expected: []string{"val1", "val3", "val4"},
		},
		{
			name:     "unknown_group_with_ok_user",
			username: "user1",
			groups:   []string{"abc", "xyz"}, // nothing wrong with groups that are not configured in our CM (but they need a known user)
			expected: []string{"val1", "val2"},
		},
		{
			name:     "unknown_user_and_group",
			username: "user4",
			groups:   []string{"group4"},
			expected: []string{}, // fine to have unknown users *and* groups, but they get no approved filter values
		},
		{
			name:     "admin_group",
			username: "blubb",
			groups:   []string{"group0"},
			expected: nil,
			skip:     true,
		},
	}

	app := &App{}
	app.WithConfig()
	app.Cfg.Admin.LabelStoreKind = "configmap"     // this also the default value
	app.Cfg.Admin.LabelStoreFile = "nested-labels" // file we load from disk (minus extension)
	app.Cfg.Admin.GroupBypass = false

	configMapLinear := ConfigMapHandler{}
	configMapLinear.Connect(*app)

	for _, tc := range cases {

		t.Run(tc.name, func(t *testing.T) {

			// nested (new) CM format
			labels, skip := configMapLinear.GetLabels(OAuthToken{PreferredUsername: tc.username, Groups: tc.groups}, app)
			happy := assert.ElementsMatch(t, tc.expected, labels)
			happy = happy && assert.Equal(t, tc.skip, skip)

			log.Info().Bool("passed", happy).Str("name", tc.name).Msg("Labelstore nested CM test")
		})
	}
}
