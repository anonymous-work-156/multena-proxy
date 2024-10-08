package main

import (
	"fmt"
	"maps"
	"strings"

	"github.com/rs/zerolog/log"

	enforcer "github.com/prometheus-community/prom-label-proxy/injectproxy"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

type PromQLError struct {
	// we will be wrapping error messages so that we can express them in JSON format
	Err error
}

func (e *PromQLError) Error() string {
	// other errorType values defined by Prometheus include "internal" and "not_acceptable"
	return fmt.Sprintf(`{"status":"error","errorType":"bad_data","error": "%v"}`, e.Err)
}

func (e *PromQLError) Unwrap() error { return e.Err }

// PromQLEnforcer is a struct with methods to enforce specific rules on Prometheus Query Language (PromQL) queries.
type PromQLEnforcer struct{}

// Enforce enhances a given PromQL query string with additional label matchers,
// ensuring that the query complies with the allowed tenant labels and specified label match.
// It returns the enhanced query or an error if the query cannot be parsed or is not compliant.
func (PromQLEnforcer) Enforce(query string, allowedTenantLabelValues []string, tenantLabelName string, errorOnIllegalTenantValue bool) (string, error) {
	log.Trace().Str("function", "enforcer").Str("input query", query).Msg("")

	if query == "" {
		operator := "="
		if len(allowedTenantLabelValues) > 1 {
			operator = "=~"
		}
		query = fmt.Sprintf("{%s%s\"%s\"}",
			tenantLabelName,
			operator,
			strings.Join(allowedTenantLabelValues, "|"))
		log.Trace().Str("function", "enforcer").Str("default query", query).Msg("")
	}

	expr, err := parser.ParseExpr(query)
	if err != nil {
		log.Warn().Msg("Failed to parse query.")
		return "", &PromQLError{err}
	}

	extractedLabelInfo, err := extractPromTenantValues(expr, tenantLabelName)
	if err != nil {
		log.Warn().Msg("The query cannot be handled because of a problem with tenant label values and/or operators.")
		return "", &PromQLError{err}
	}

	processedLabelInfo, err := processLabelValues(extractedLabelInfo, allowedTenantLabelValues, errorOnIllegalTenantValue)
	if err != nil {
		log.Warn().Msg("Unable to process the label values.")
		return "", &PromQLError{err}
	}

	labelEnforcer := enforcer.NewPromQLEnforcer(false, &labels.Matcher{
		Name:  tenantLabelName,
		Type:  processedLabelInfo.Type,
		Value: processedLabelInfo.Value,
	})

	err = labelEnforcer.EnforceNode(expr)
	if err != nil {
		log.Warn().Msg("The promql label enforcer was unhappy.")
		return "", &PromQLError{err}
	}
	log.Trace().Str("function", "enforcer").Str("approved query", expr.String()).Msg("")
	log.Trace().Msg("Returning approved expression.")
	return expr.String(), nil
}

// extractPromTenantValues parses a PromQL expression and extracts labels and their values.
// Returns a struct containing the operator and tenant label value which were found.
// An error is returned if conflicting operator and/or values are found for the tenant label.
// NOTE: It is crude to insist that only one distinct operator and value are associated with the tenant label; it forbids some valid queries.
func extractPromTenantValues(expr parser.Expr, tenantLabelName string) (*LabelValueInfo, error) {
	var info map[LabelValueInfo]bool = make(map[LabelValueInfo]bool)
	parser.Inspect(expr, func(node parser.Node, path []parser.Node) error {
		if vector, ok := node.(*parser.VectorSelector); ok {
			for _, matcher := range vector.LabelMatchers {
				if matcher.Name != tenantLabelName {
					continue
				}
				thisinfo := LabelValueInfo{matcher.Value, matcher.Type}
				_, ok = info[thisinfo]
				if !ok {
					info[thisinfo] = true
				}
			}
		}
		return nil
	})
	if len(info) == 1 {
		for v := range maps.Keys(info) {
			// WTF Go, is this the best way?
			return &v, nil
		}
	}
	if len(info) > 1 {
		return nil, fmt.Errorf("found conflicting values or operators for tenant label")
	}
	return nil, nil
}
