package main

import (
	"slices"
	"testing"

	"github.com/rs/zerolog/log"
)

func Test_promqlEnforcer(t *testing.T) {

	type args struct {
		query                     string
		allowedTenantLabelValues  []string
		errorOnIllegalTenantValue bool
		metricsTenantOptional     []string
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
				query:                     "up{namespace=\"namespace1\"}",
				allowedTenantLabelValues:  []string{"namespace1"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"up{namespace=\"namespace1\"}"},
			wantErr: false,
		},
		{
			name: "1 of 1, doubled up",
			args: args{
				query:                     "up{namespace=\"namespace1\",bob=\"joe\"} * up{namespace=\"namespace1\",foo=\"bar\"}",
				allowedTenantLabelValues:  []string{"namespace1"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"up{bob=\"joe\",namespace=\"namespace1\"} * up{foo=\"bar\",namespace=\"namespace1\"}"},
			wantErr: false,
		},
		{
			name: "1 of 1, with regex",
			args: args{
				query:                     "up{namespace=~\"namespace1\"}", // should be identical to using the = operator
				allowedTenantLabelValues:  []string{"namespace1"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"up{namespace=\"namespace1\"}"},
			wantErr: false,
		},
		{
			name: "1 of 1, doubled with regex",
			args: args{
				query:                     "up{namespace=~\".*\"} * up{namespace=~\".*\"}",
				allowedTenantLabelValues:  []string{"namespace11"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"up{namespace=\"namespace11\"} * up{namespace=\"namespace11\"}"},
			wantErr: false,
		},
		{
			name: "1 of 1, implied",
			args: args{
				query:                     "up",
				allowedTenantLabelValues:  []string{"namespace1"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"up{namespace=\"namespace1\"}"},
			wantErr: false,
		},
		{
			name: "1 of 1, forbidden",
			args: args{
				query:                     "{__name__=\"up\",namespace=\"namespace2\"}",
				allowedTenantLabelValues:  []string{"namespace1"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"{__name__=\"up\",namespace!=\"\",namespace=\"\"}"},
			wantErr: false,
		},
		{
			name: "1 of 1, sneaky forbidden",
			args: args{
				query:                     "up{namespace=\"namespace11\",other_label=\"foo\"}",
				allowedTenantLabelValues:  []string{"namespace1"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"up{namespace!=\"\",namespace=\"\",other_label=\"foo\"}"},
			wantErr: false,
		},
		{
			name: "1 of 1, complex query",
			args: args{
				query:                     "sum(kube_pod_container_resource_requests{node!=\"\",resource=\"memory\"} * on(cluster,pod,namespace) group_left(phase) kube_pod_status_phase{phase=\"Running\"}) by (node,cluster,pod,namespace)",
				allowedTenantLabelValues:  []string{"namespace1"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"sum by (node, cluster, pod, namespace) (kube_pod_container_resource_requests{namespace=\"namespace1\",node!=\"\",resource=\"memory\"} * on (cluster, pod, namespace) group_left (phase) kube_pod_status_phase{namespace=\"namespace1\",phase=\"Running\"})"},
			wantErr: false,
		},
		{
			name: "1 of 1, rate query",
			args: args{
				query:                     "rate(container_cpu_usage_seconds_total[5m])",
				allowedTenantLabelValues:  []string{"namespace1"},
				errorOnIllegalTenantValue: false,
				metricsTenantOptional:     []string{"irrelevantnoise"},
			},
			want:    []string{"rate(container_cpu_usage_seconds_total{namespace=\"namespace1\"}[5m])"},
			wantErr: false,
		},
		{
			name: "1 of 1, two part rate query",
			args: args{
				query:                     "rate(container_cpu_usage_seconds_total{workload=\"a\"}[5m]) / rate(container_cpu_usage_seconds_total{workload=\"b\"}[5m])",
				allowedTenantLabelValues:  []string{"namespace1"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"rate(container_cpu_usage_seconds_total{namespace=\"namespace1\",workload=\"a\"}[5m]) / rate(container_cpu_usage_seconds_total{namespace=\"namespace1\",workload=\"b\"}[5m])"},
			wantErr: false,
		},
		{
			name: "1 of 1, optional tenant",
			args: args{
				query:                     "up{namespace=\"namespace2\"}",
				allowedTenantLabelValues:  []string{"namespace1"},
				errorOnIllegalTenantValue: false,
				metricsTenantOptional:     []string{"up"},
			},
			want:    []string{"up{namespace!=\"\",namespace=\"\"}"},
			wantErr: false,
		},
		{
			name: "1 of 1, optional tenant complex",
			args: args{
				query:                     "sum(rate(container_cpu_usage_seconds_total{namespace=\"namespace1\"}[5m])) / sum(machine_cpu_cores{cluster=\"mahcluster\"}) * 100",
				allowedTenantLabelValues:  []string{"namespace1"},
				errorOnIllegalTenantValue: false,
				metricsTenantOptional:     []string{"machine_cpu_cores"},
			},
			want:    []string{"sum(rate(container_cpu_usage_seconds_total{namespace=\"namespace1\"}[5m])) / sum(machine_cpu_cores{cluster=\"mahcluster\",namespace=~\"namespace1|\"}) * 100"},
			wantErr: false,
		},
		{
			name: "1 of 1, optional tenant complex 2",
			args: args{
				query:                     "sum(machine_cpu_cores{cluster=\"mahcluster\",namespace=~\".*\"}) / sum(rate(container_cpu_usage_seconds_total{namespace=~\".*\"}[5m])) * 100",
				allowedTenantLabelValues:  []string{"namespace1"},
				errorOnIllegalTenantValue: false,
				metricsTenantOptional:     []string{"machine_cpu_cores"},
			},
			want:    []string{"sum(machine_cpu_cores{cluster=\"mahcluster\",namespace=~\"namespace1|\"}) / sum(rate(container_cpu_usage_seconds_total{namespace=\"namespace1\"}[5m])) * 100"},
			wantErr: false,
		},
		{
			name: "1 of 1, optional tenant complex fail",
			args: args{
				query:                     "sum(rate(container_cpu_usage_seconds_total{namespace=\"namespace2\"}[5m])) / sum(machine_cpu_cores{cluster=\"mahcluster\"}) * 100",
				allowedTenantLabelValues:  []string{"namespace1"},
				errorOnIllegalTenantValue: true,
				metricsTenantOptional:     []string{"machine_cpu_cores"},
			},
			want:    []string{""},
			wantErr: true,
		},
		{
			name: "1 of 1, optional tenant complex fail 2",
			args: args{
				query:                     "sum(rate(container_cpu_usage_seconds_total{namespace=\"namespace2\"}[5m])) / sum(machine_cpu_cores{cluster=\"mahcluster\"}) * 100",
				allowedTenantLabelValues:  []string{"namespace1"},
				errorOnIllegalTenantValue: false,
				metricsTenantOptional:     []string{"machine_cpu_cores"},
			},
			want:    []string{"sum(rate(container_cpu_usage_seconds_total{namespace!=\"\",namespace=\"\"}[5m])) / sum(machine_cpu_cores{cluster=\"mahcluster\",namespace=~\"namespace1|\"}) * 100"},
			wantErr: false,
		},
		{
			name: "1 of 2",
			args: args{
				query:                     "{__name__=\"up\",namespace=\"namespace1\"}",
				allowedTenantLabelValues:  []string{"namespace1", "namespace2"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"{__name__=\"up\",namespace=\"namespace1\"}"},
			wantErr: false,
		},
		{
			name: "2 of 2, odd query",
			args: args{
				query:                     "count(count({__name__!=\"\"}) by (__name__))",
				allowedTenantLabelValues:  []string{"namespace1", "namespace2"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"count(count by (__name__) ({__name__!=\"\",namespace=~\"namespace1|namespace2\"}))"},
			wantErr: false,
		},
		{
			name: "2 of 2",
			args: args{
				query:                     "up{namespace=~\"namespace1|namespace2\"}",
				allowedTenantLabelValues:  []string{"namespace1", "namespace2"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"up{namespace=~\"namespace1|namespace2\"}", "up{namespace=~\"namespace2|namespace1\"}"},
			wantErr: false,
		},
		{
			name: "2 of 2, with regex",
			args: args{
				query:                     "up{namespace=~\"namespace.*\"}",
				allowedTenantLabelValues:  []string{"namespace25", "namespace23"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"up{namespace=~\"namespace23|namespace25\"}", "up{namespace=~\"namespace25|namespace23\"}"},
			wantErr: false,
		},
		{
			name: "2 of 2, forbidden",
			args: args{
				query:                     "up{namespace=~\"namespace1|namespace3\"}",
				allowedTenantLabelValues:  []string{"namespace1", "namespace2"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"up{namespace=\"namespace1\"}"},
			wantErr: false,
		},
		{
			name: "2 of 2, sneaky forbidden",
			args: args{
				query:                     "up{namespace=~\"namespace2|namespace11\"}",
				allowedTenantLabelValues:  []string{"namespace1", "namespace2"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"up{namespace=\"namespace2\"}"},
			wantErr: false,
		},
		{
			name: "2 of 3",
			args: args{
				query:                     "up{namespace=~\"namespace1|namespace2\"}",
				allowedTenantLabelValues:  []string{"namespace1", "namespace2", "namespace3"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"up{namespace=~\"namespace1|namespace2\"}", "up{namespace=~\"namespace2|namespace1\"}"},
			wantErr: false,
		},
		{
			name: "2 of 2, implied",
			args: args{
				query:                     "up",
				allowedTenantLabelValues:  []string{"namespace", "grrr"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"up{namespace=~\"namespace|grrr\"}", "up{namespace=~\"grrr|namespace\"}"},
			wantErr: false,
		},
		{
			name: "1 of 3, with regex",
			args: args{
				query:                     "up{namespace=~\".*2\"}",
				allowedTenantLabelValues:  []string{"namespace1", "namespace2", "namespace3"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"up{namespace=\"namespace2\"}"},
			wantErr: false,
		},
		{
			name: "2 of 3, with not",
			args: args{
				query:                     "up{namespace!=\"namespace2\"}",
				allowedTenantLabelValues:  []string{"namespace1", "namespace2", "namespace3"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"up{namespace=~\"namespace1|namespace3\"}", "up{namespace=~\"namespace3|namespace1\"}"},
			wantErr: false,
		},
		{
			name: "2 of 3, with not regex",
			args: args{
				query:                     "up{namespace!~\".*2\"}",
				allowedTenantLabelValues:  []string{"namespace1", "namespace2", "namespace3"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"up{namespace=~\"namespace1|namespace3\"}", "up{namespace=~\"namespace3|namespace1\"}"},
			wantErr: false,
		},
		{
			name: "2 of 3, with not regex 2",
			args: args{
				query:                     "up{namespace!~\"namespace3\"}",
				allowedTenantLabelValues:  []string{"namespace1", "namespace2", "namespace3"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"up{namespace=~\"namespace1|namespace2\"}", "up{namespace=~\"namespace2|namespace1\"}"},
			wantErr: false,
		},
		{
			name: "3 of 3, differing matchers",
			args: args{
				query:                     "sum(rate(container_cpu_usage_seconds_total{namespace=\"namespace1\"}[5m])) / sum(rate(container_cpu_usage_seconds_total{namespace!=\"namespace1\"}[5m])) * 100",
				allowedTenantLabelValues:  []string{"namespace1", "namespace2", "namespace3"},
				errorOnIllegalTenantValue: false,
			},
			want:    []string{"sum(rate(container_cpu_usage_seconds_total{namespace=\"namespace1\"}[5m])) / sum(rate(container_cpu_usage_seconds_total{namespace=~\"namespace2|namespace3\"}[5m])) * 100"},
			wantErr: false,
		},
	}

	enforcer := PromQLEnforcer{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log.Info().Str("name", tt.name).Msg("PromQL enforcer test")

			config := Config{}
			config.Thanos.TenantLabel = "namespace"
			config.Thanos.ErrorOnIllegalTenantValue = tt.args.errorOnIllegalTenantValue
			config.Thanos.MetricsTenantOptional = tt.args.metricsTenantOptional

			got, err := enforcer.Enforce(tt.args.query, tt.args.allowedTenantLabelValues, &config)
			if (err != nil) != tt.wantErr {
				t.Errorf("promqlEnforcer() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if !slices.Contains(tt.want, got) {
				t.Errorf("promqlEnforcer() = %v, want = %v", got, tt.want[0])
			}
		})
	}
}
