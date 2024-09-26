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
			name: "1 of 1, as regex",
			args: args{
				query:        "up{namespace=~\"namespace1\"}", // should be identical to using the = operator
				tenantLabels: map[string]bool{"namespace1": true},
			},
			want:    []string{"up{namespace=\"namespace1\"}"},
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
			want:    []string{""},
			wantErr: true,
		},
		{
			name: "1 of 1, sneaky forbidden",
			args: args{
				query:        "up{namespace=\"namespace11\"}",
				tenantLabels: map[string]bool{"namespace1": true},
			},
			want:    []string{""},
			wantErr: true,
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
			name: "2 of 2, forbidden",
			args: args{
				query:        "up{namespace=~\"namespace1|namespace3\"}",
				tenantLabels: map[string]bool{"namespace1": true, "namespace2": true},
			},
			want:    []string{""},
			wantErr: true,
		},
		{
			name: "2 of 2, sneaky forbidden",
			args: args{
				query:        "up{namespace=~\"namespace2|namespace11\"}",
				tenantLabels: map[string]bool{"namespace1": true, "namespace2": true},
			},
			want:    []string{""},
			wantErr: true,
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
			name: "with regex",
			args: args{
				query:        "up{namespace=~\"namespace.*\"}",
				tenantLabels: map[string]bool{"namespace1": true, "namespace2": true, "namespace3": true},
			},
			want:    []string{""},
			wantErr: true, // this could be made to not fail, with enough work
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
