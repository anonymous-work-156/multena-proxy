package main

import (
	"slices"
	"testing"

	"github.com/rs/zerolog/log"
)

func TestLogqlEnforcer(t *testing.T) {
	type args struct {
		query                     string
		allowedTenantLabelValues  []string
		errorOnIllegalTenantValue bool
	}

	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "valid query and tenant labels",
			args: args{
				query:                     "{kubernetes_namespace_name=\"test\"}",
				allowedTenantLabelValues:  []string{"test"},
				errorOnIllegalTenantValue: true,
			},
			want:    []string{"{kubernetes_namespace_name=\"test\"}"},
			wantErr: false,
		},
		{
			name: "valid query and tenant labels, multi allowed",
			args: args{
				query:                     "{kubernetes_namespace_name=\"test\"}",
				allowedTenantLabelValues:  []string{"test", "test2", "test3"},
				errorOnIllegalTenantValue: true,
			},
			want:    []string{"{kubernetes_namespace_name=\"test\"}"},
			wantErr: false,
		},
		{
			name: "valid query and tenant labels, not equal, multi allowed",
			args: args{
				query:                     `{other_label="foo",kubernetes_namespace_name!="test"}`,
				allowedTenantLabelValues:  []string{"test", "test2", "test3"},
				errorOnIllegalTenantValue: true,
			},
			want:    []string{`{other_label="foo", kubernetes_namespace_name=~"test2|test3"}`, `{other_label="foo", kubernetes_namespace_name=~"test3|test2"}`},
			wantErr: false,
		},
		{
			name: "valid query and tenant labels, multi regex, multi allowed",
			args: args{
				query:                     "{kubernetes_namespace_name=~\"test.+\"}",
				allowedTenantLabelValues:  []string{"test", "test2", "test3"},
				errorOnIllegalTenantValue: true,
			},
			want:    []string{"{kubernetes_namespace_name=~\"test2|test3\"}", "{kubernetes_namespace_name=~\"test3|test2\"}"},
			wantErr: false,
		},
		{
			name: "empty query and valid tenant labels",
			args: args{
				query:                     "",
				allowedTenantLabelValues:  []string{"test"},
				errorOnIllegalTenantValue: true,
			},
			want:    []string{"{kubernetes_namespace_name=\"test\"}"},
			wantErr: false,
		},
		{
			name: "valid query and invalid tenant labels, no error",
			args: args{
				query:                     "{kubernetes_namespace_name=\"invalid\"}",
				allowedTenantLabelValues:  []string{"test"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"{kubernetes_namespace_name=\"\", kubernetes_namespace_name!=\"\"}"},
			wantErr: false,
		},
		{
			name: "valid query and invalid tenant labels, no error 2",
			args: args{
				query:                     "{other_label=\"bob\", kubernetes_namespace_name=\"test3\"}",
				allowedTenantLabelValues:  []string{"test1", "test2"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"{other_label=\"bob\", kubernetes_namespace_name=\"\", kubernetes_namespace_name!=\"\"}"},
			wantErr: false,
		},
		{
			name: "valid query and invalid tenant labels, no error 3",
			args: args{
				query:                     "{other_label=\"bob\", kubernetes_namespace_name=\"test3\", kubernetes_namespace_name=\"test3\"}",
				allowedTenantLabelValues:  []string{"test1", "test2"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"{other_label=\"bob\", kubernetes_namespace_name=\"\", kubernetes_namespace_name!=\"\"}"},
			wantErr: false,
		},
		{
			name: "valid query and invalid tenant labels, want error",
			args: args{
				query:                     "{kubernetes_namespace_name=\"invalid\"}",
				allowedTenantLabelValues:  []string{"test"},
				errorOnIllegalTenantValue: true,
			},
			want:    []string{""},
			wantErr: true,
		},
		{
			name: "valid query and invalid tenant labels, not equal, want error",
			args: args{
				query:                     "{kubernetes_namespace_name!=\"test\"}",
				allowedTenantLabelValues:  []string{"test"},
				errorOnIllegalTenantValue: true,
			},
			want:    []string{""},
			wantErr: true,
		},
		{
			name: "valid query and invalid tenant labels, regex, want error",
			args: args{
				query:                     "{kubernetes_namespace_name=~\"bad.*\"}",
				allowedTenantLabelValues:  []string{"test"},
				errorOnIllegalTenantValue: true,
			},
			want:    []string{""},
			wantErr: true,
		},
		{
			name: "conflicting tenant labels, part 1",
			args: args{
				query:                     "{kubernetes_namespace_name=\"test1\", kubernetes_namespace_name=\"test1\"}",
				allowedTenantLabelValues:  []string{"test1", "test2"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"{kubernetes_namespace_name=\"test1\", kubernetes_namespace_name=\"test1\"}"},
			wantErr: false,
		},
		{
			name: "conflicting tenant labels, part 2",
			args: args{
				query:                     "{other_label=\"bob\", kubernetes_namespace_name=\"test1\", kubernetes_namespace_name!=\"test1\"}",
				allowedTenantLabelValues:  []string{"test1", "test2"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{""},
			wantErr: true, // found multiple values or operators for tenant label
		},
		{
			name: "conflicting tenant labels, part 3",
			args: args{
				query:                     "{kubernetes_namespace_name=\"test1\", other_label=\"bob\", kubernetes_namespace_name=\"test2\"}",
				allowedTenantLabelValues:  []string{"test1", "test2"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{""},
			wantErr: true, // found multiple values or operators for tenant label
		},
		{
			name: "conflicting tenant labels, part 3b",
			args: args{
				query:                     "{kubernetes_namespace_name=\"test1\", other_label=\"bob\", kubernetes_namespace_name=\"test2\"}",
				allowedTenantLabelValues:  []string{"test1", "test2"},
				errorOnIllegalTenantValue: true,
			},
			want:    []string{""},
			wantErr: true,
		},
		{
			name: "elaborate query 1",
			args: args{
				query:                     `count_over_time({job="mysql"}[5m])`,
				allowedTenantLabelValues:  []string{"test"},
				errorOnIllegalTenantValue: true,
			},
			want:    []string{`count_over_time({job="mysql", kubernetes_namespace_name="test"}[5m])`},
			wantErr: false,
		},
		{
			name: "elaborate query 2",
			args: args{
				query:                     `sum by (host)(rate({job="mysql"} |= "error" != "timeout" | json | duration>10s[1m]))`,
				allowedTenantLabelValues:  []string{"test"},
				errorOnIllegalTenantValue: true,
			},
			want:    []string{`sum by (host)(rate({job="mysql", kubernetes_namespace_name="test"} |= "error" != "timeout" | json | duration>10s[1m]))`},
			wantErr: false,
		},
		{
			name: "elaborate query 3",
			args: args{
				query:                     `(sum by (cluster)(rate({job="foo"} |= "bar" | logfmt | bazz="buzz"[5m])) / sum by (cluster)(rate({job="foo"} |= "bar" | logfmt | bazz="buzz"[5m])))`,
				allowedTenantLabelValues:  []string{"test"},
				errorOnIllegalTenantValue: true,
			},
			want:    []string{`(sum by (cluster)(rate({job="foo", kubernetes_namespace_name="test"} |= "bar" | logfmt | bazz="buzz"[5m])) / sum by (cluster)(rate({job="foo", kubernetes_namespace_name="test"} |= "bar" | logfmt | bazz="buzz"[5m])))`},
			wantErr: false,
		},
	}

	enforcer := LogQLEnforcer{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log.Info().Str("name", tt.name).Msg("LogQL enforcer test")

			config := Config{}
			config.Loki.TenantLabel = "kubernetes_namespace_name"
			config.Loki.ErrorOnIllegalTenantValue = tt.args.errorOnIllegalTenantValue

			got, err := enforcer.Enforce(tt.args.query, tt.args.allowedTenantLabelValues, &config)
			if (err != nil) != tt.wantErr {
				t.Errorf("logqlEnforcer() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if !slices.Contains(tt.want, got) {
				t.Errorf("logqlEnforcer() = %v, want = %v", got, tt.want[0])
			}
		})
	}
}
