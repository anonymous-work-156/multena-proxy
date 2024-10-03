package main

import (
	"testing"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/rs/zerolog/log"
)

func Test_tenantLabelValues(t *testing.T) {
	type args struct {
		give                      LabelValueInfo
		allowedTenantLabelValues  []string
		errorOnIllegalTenantValue bool
	}

	tests := []struct {
		name    string
		args    args
		want    *LabelValueInfo
		wantErr bool
	}{
		{
			name: "should fail and return empty string matcher",
			args: args{
				give:                      LabelValueInfo{"ns2", labels.MatchEqual},
				allowedTenantLabelValues:  []string{"namespace1"},
				errorOnIllegalTenantValue: false,
			},
			want:    &LabelValueInfo{"", labels.MatchEqual},
			wantErr: false,
		},
		{
			name: "should work",
			args: args{
				give:                      LabelValueInfo{"namespace1", labels.MatchEqual},
				allowedTenantLabelValues:  []string{"namespace1"},
				errorOnIllegalTenantValue: true,
			},
			want:    &LabelValueInfo{"namespace1", labels.MatchEqual},
			wantErr: false,
		},
		{
			name: "should work with non-pattern regex",
			args: args{
				give:                      LabelValueInfo{"namespace1", labels.MatchRegexp},
				allowedTenantLabelValues:  []string{"namespace1"},
				errorOnIllegalTenantValue: true,
			},
			want:    &LabelValueInfo{"namespace1", labels.MatchEqual},
			wantErr: false,
		},
		{
			name: "should fail due to equality test on regex syntax",
			args: args{
				give:                      LabelValueInfo{"one|two", labels.MatchEqual},
				allowedTenantLabelValues:  []string{"one", "two"},
				errorOnIllegalTenantValue: true,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "should work in a convoluted way",
			args: args{
				give:                      LabelValueInfo{"one|two", labels.MatchNotEqual},
				allowedTenantLabelValues:  []string{"one", "two"},
				errorOnIllegalTenantValue: true,
			},
			want:    &LabelValueInfo{"one|two", labels.MatchRegexp},
			wantErr: false,
		},
		{
			name: "should work 2",
			args: args{
				give:                      LabelValueInfo{"one|two", labels.MatchRegexp},
				allowedTenantLabelValues:  []string{"one", "two", "three"},
				errorOnIllegalTenantValue: false,
			},
			want:    &LabelValueInfo{"one|two", labels.MatchRegexp},
			wantErr: false,
		},
		{
			name: "should work 3",
			args: args{
				give:                      LabelValueInfo{"t.+", labels.MatchRegexp},
				allowedTenantLabelValues:  []string{"one", "two", "three"},
				errorOnIllegalTenantValue: false,
			},
			want:    &LabelValueInfo{"two|three", labels.MatchRegexp},
			wantErr: false,
		},
		{
			name: "should work 4",
			args: args{
				give:                      LabelValueInfo{"one|two", labels.MatchNotRegexp},
				allowedTenantLabelValues:  []string{"one", "two", "three"},
				errorOnIllegalTenantValue: false,
			},
			want:    &LabelValueInfo{"three", labels.MatchEqual},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log.Info().Str("name", tt.name).Msg("Tenant label value enforcer test")
			got, err := processLabelValues(&tt.args.give, tt.args.allowedTenantLabelValues, tt.args.errorOnIllegalTenantValue)
			if (err != nil) != tt.wantErr {
				t.Errorf("processLabelValues() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if (got == nil) != (tt.want == nil) || (got != nil && *got != *tt.want) {
				t.Errorf("processLabelValues() = %v, want = %v", got, tt.want)
			}
		})
	}
}
