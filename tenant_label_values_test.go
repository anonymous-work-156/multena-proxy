package main

import (
	"testing"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/rs/zerolog/log"
)

func Test_tenantLabelValues(t *testing.T) {

	log.Info().Caller().Msg("Start Test_tenantLabelValues().")
	defer log.Info().Msg("End Test_tenantLabelValues().")

	type args struct {
		give                     LabelValueInfo
		allowedTenantLabelValues []string
	}

	tests := []struct {
		name    string
		args    args
		want    *LabelValueInfo
		wantErr error
	}{
		{
			name: "should fail due to illegal label value",
			args: args{
				give:                     LabelValueInfo{"ns2", labels.MatchEqual},
				allowedTenantLabelValues: []string{"namespace1"},
			},
			want:    nil,
			wantErr: ErrUnauthorizedLabelValue,
		},
		{
			name: "should fail due to illegal label value 2",
			args: args{
				give:                     LabelValueInfo{"ns2", labels.MatchRegexp},
				allowedTenantLabelValues: []string{"namespace1"},
			},
			want:    nil,
			wantErr: ErrNoLabelMatch,
		},
		{
			name: "should work",
			args: args{
				give:                     LabelValueInfo{"namespace1", labels.MatchEqual},
				allowedTenantLabelValues: []string{"namespace1"},
			},
			want:    &LabelValueInfo{"namespace1", labels.MatchEqual},
			wantErr: nil,
		},
		{
			name: "should work with non-pattern regex",
			args: args{
				give:                     LabelValueInfo{"namespace1", labels.MatchRegexp},
				allowedTenantLabelValues: []string{"namespace1"},
			},
			want:    &LabelValueInfo{"namespace1", labels.MatchEqual},
			wantErr: nil,
		},
		{
			name: "should fail due to equality test on regex syntax",
			args: args{
				give:                     LabelValueInfo{"one|two", labels.MatchEqual},
				allowedTenantLabelValues: []string{"one", "two"},
			},
			want:    nil,
			wantErr: ErrUnauthorizedLabelValue,
		},
		{
			name: "should work in a convoluted way",
			args: args{
				give:                     LabelValueInfo{"one|two", labels.MatchNotEqual},
				allowedTenantLabelValues: []string{"one", "two"},
			},
			want:    &LabelValueInfo{"one|two", labels.MatchRegexp},
			wantErr: nil,
		},
		{
			name: "should work 2",
			args: args{
				give:                     LabelValueInfo{"one|two", labels.MatchRegexp},
				allowedTenantLabelValues: []string{"one", "two", "three"},
			},
			want:    &LabelValueInfo{"one|two", labels.MatchRegexp},
			wantErr: nil,
		},
		{
			name: "should work 3",
			args: args{
				give:                     LabelValueInfo{"t.+", labels.MatchRegexp},
				allowedTenantLabelValues: []string{"one", "two", "three"},
			},
			want:    &LabelValueInfo{"two|three", labels.MatchRegexp},
			wantErr: nil,
		},
		{
			name: "should work 4",
			args: args{
				give:                     LabelValueInfo{"one|two", labels.MatchNotRegexp},
				allowedTenantLabelValues: []string{"one", "two", "three"},
			},
			want:    &LabelValueInfo{"three", labels.MatchEqual},
			wantErr: nil,
		},
		{
			name: "should work despite some illegal values",
			args: args{
				give:                     LabelValueInfo{"one|two|four|five|ten", labels.MatchRegexp},
				allowedTenantLabelValues: []string{"one", "two", "three"},
			},
			want:    &LabelValueInfo{"one|two", labels.MatchRegexp},
			wantErr: nil,
		},
		{
			name: "should work including empty string 1",
			args: args{
				give:                     LabelValueInfo{"one|two", labels.MatchRegexp},
				allowedTenantLabelValues: []string{"one", "two", ""},
			},
			want:    &LabelValueInfo{"one|two", labels.MatchRegexp},
			wantErr: nil,
		},
		{
			name: "should work including empty string 2",
			args: args{
				give:                     LabelValueInfo{".*", labels.MatchRegexp},
				allowedTenantLabelValues: []string{"one", "two", ""},
			},
			want:    &LabelValueInfo{"one|two|", labels.MatchRegexp},
			wantErr: nil,
		},
		{
			name: "should work including empty string 3",
			args: args{
				give:                     LabelValueInfo{"", labels.MatchEqual},
				allowedTenantLabelValues: []string{"one", "two", ""},
			},
			want:    &LabelValueInfo{"", labels.MatchEqual},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log.Info().Str("name", tt.name).Msg("Tenant label value enforcer test")
			got, err := processLabelValues(&tt.args.give, tt.args.allowedTenantLabelValues)
			if err != tt.wantErr {
				t.Errorf("processLabelValues() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if (got == nil) != (tt.want == nil) || (got != nil && *got != *tt.want) {
				t.Errorf("processLabelValues() = %v, want = %v", got, tt.want)
			}
		})
	}
}
