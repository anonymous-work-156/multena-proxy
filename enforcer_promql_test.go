package main

import (
	"slices"
	"testing"

	"github.com/rs/zerolog/log"
)

func Test_promqlEnforcer(t *testing.T) {
	type args struct {
		query        string
		tenantLabels map[string]bool
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "1 of 1",
			args: args{
				query:        "up{namespace=\"namespace1\"}",
				tenantLabels: map[string]bool{"namespace1": true},
			},
			want:    []string{"up{namespace=\"namespace1\"}"},
			wantErr: false,
		},
		{
			name: "1 of 1, with regex",
			args: args{
				query:        "up{namespace=~\"namespace1\"}", // should be identical to using the = operator
				tenantLabels: map[string]bool{"namespace1": true},
			},
			want:    []string{"up{namespace=\"namespace1\"}"},
			wantErr: false,
		},
		{
			name: "1 of 1, with regex 2",
			args: args{
				query:        "up{namespace=~\".*\"}",
				tenantLabels: map[string]bool{"namespace11": true},
			},
			want:    []string{"up{namespace=\"namespace11\"}"},
			wantErr: false,
		},
		{
			name: "1 of 1, implied",
			args: args{
				query:        "up",
				tenantLabels: map[string]bool{"namespace1": true},
			},
			want:    []string{"up{namespace=\"namespace1\"}"},
			wantErr: false,
		},
		{
			name: "1 of 1, forbidden",
			args: args{
				query:        "{__name__=\"up\",namespace=\"namespace2\"}",
				tenantLabels: map[string]bool{"namespace1": true},
			},
			want:    []string{"{__name__=\"up\",namespace=\"\"}"},
			wantErr: false,
		},
		{
			name: "1 of 1, sneaky forbidden",
			args: args{
				query:        "up{namespace=\"namespace11\"}",
				tenantLabels: map[string]bool{"namespace1": true},
			},
			want:    []string{"up{namespace=\"\"}"},
			wantErr: false,
		},
		{
			name: "1 of 2",
			args: args{
				query:        "{__name__=\"up\",namespace=\"namespace1\"}",
				tenantLabels: map[string]bool{"namespace1": true, "namespace2": true},
			},
			want:    []string{"{__name__=\"up\",namespace=\"namespace1\"}"},
			wantErr: false,
		},
		{
			name: "2 of 2",
			args: args{
				query:        "up{namespace=~\"namespace1|namespace2\"}",
				tenantLabels: map[string]bool{"namespace1": true, "namespace2": true},
			},
			want:    []string{"up{namespace=~\"namespace1|namespace2\"}", "up{namespace=~\"namespace2|namespace1\"}"},
			wantErr: false,
		},
		{
			name: "2 of 2, with regex",
			args: args{
				query:        "up{namespace=~\"namespace.*\"}",
				tenantLabels: map[string]bool{"namespace25": true, "namespace23": true},
			},
			want:    []string{"up{namespace=~\"namespace.*\",namespace=~\"namespace23|namespace25\"}", "up{namespace=~\"namespace.*\",namespace=~\"namespace25|namespace23\"}"},
			wantErr: false, // NOTE: this 'want' above includes the now-redundant input regex due to the implementation of PromQLEnforcer
		},
		{
			name: "2 of 2, forbidden",
			args: args{
				query:        "up{namespace=~\"namespace1|namespace3\"}",
				tenantLabels: map[string]bool{"namespace1": true, "namespace2": true},
			},
			want:    []string{"up{namespace=\"namespace1\"}"},
			wantErr: false,
		},
		{
			name: "2 of 2, sneaky forbidden",
			args: args{
				query:        "up{namespace=~\"namespace2|namespace11\"}",
				tenantLabels: map[string]bool{"namespace1": true, "namespace2": true},
			},
			want:    []string{"up{namespace=\"namespace2\"}"},
			wantErr: false,
		},
		{
			name: "2 of 3",
			args: args{
				query:        "up{namespace=~\"namespace1|namespace2\"}",
				tenantLabels: map[string]bool{"namespace1": true, "namespace2": true, "namespace3": true},
			},
			want:    []string{"up{namespace=~\"namespace1|namespace2\"}", "up{namespace=~\"namespace2|namespace1\"}"},
			wantErr: false,
		},
		{
			name: "2 of 2, implied",
			args: args{
				query:        "up",
				tenantLabels: map[string]bool{"namespace": true, "grrr": true},
			},
			want:    []string{"up{namespace=~\"namespace|grrr\"}", "up{namespace=~\"grrr|namespace\"}"},
			wantErr: false,
		},
		{
			name: "1 of 3, with regex",
			args: args{
				query:        "up{namespace=~\".*2\"}",
				tenantLabels: map[string]bool{"namespace1": true, "namespace2": true, "namespace3": true},
			},
			want:    []string{"up{namespace=\"namespace2\"}"},
			wantErr: false,
		},
		{
			name: "2 of 3, with not",
			args: args{
				query:        "up{namespace!=\"namespace2\"}",
				tenantLabels: map[string]bool{"namespace1": true, "namespace2": true, "namespace3": true},
			},
			want:    []string{"up{namespace!=\"namespace2\",namespace=~\"namespace1|namespace3\"}", "up{namespace!=\"namespace2\",namespace=~\"namespace3|namespace1\"}"},
			wantErr: false, // NOTE: this 'want' above includes the now-redundant input regex due to the implementation of PromQLEnforcer
		},
		{
			name: "2 of 3, with not regex",
			args: args{
				query:        "up{namespace!~\".*2\"}",
				tenantLabels: map[string]bool{"namespace1": true, "namespace2": true, "namespace3": true},
			},
			want:    []string{"up{namespace!~\".*2\",namespace=~\"namespace1|namespace3\"}", "up{namespace!~\".*2\",namespace=~\"namespace3|namespace1\"}"},
			wantErr: false, // NOTE: this 'want' above includes the now-redundant input regex due to the implementation of PromQLEnforcer
		},
		{
			name: "2 of 3, with not regex 2",
			args: args{
				query:        "up{namespace!~\"namespace3\"}",
				tenantLabels: map[string]bool{"namespace1": true, "namespace2": true, "namespace3": true},
			},
			want:    []string{"up{namespace!~\"namespace3\",namespace=~\"namespace1|namespace2\"}", "up{namespace!~\"namespace3\",namespace=~\"namespace2|namespace1\"}"},
			wantErr: false, // NOTE: this 'want' above includes the now-redundant input regex due to the implementation of PromQLEnforcer
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log.Info().Str("name", tt.name).Msg("PromQL enforcer test")
			got, err := PromQLEnforcer{}.Enforce(tt.args.query, tt.args.tenantLabels, "namespace")
			if (err != nil) != tt.wantErr {
				t.Errorf("promqlEnforcer() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if !slices.Contains(tt.want, got) {
				t.Errorf("promqlEnforcer() = %v, want = %v", got, tt.want[0])
			}
		})
	}
}
