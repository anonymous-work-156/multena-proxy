package main

import (
	"fmt"
	"maps"
	"strings"

	"github.com/rs/zerolog/log"

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
func (PromQLEnforcer) Enforce(query string, allowedTenantLabelValues []string, config *Config) (string, error) {
	log.Trace().Str("function", "enforcer").Str("input query", query).Msg("")

	if query == "" {
		operator := "="
		if len(allowedTenantLabelValues) > 1 {
			operator = "=~"
		}
		query = fmt.Sprintf("{%s%s\"%s\"}",
			config.Thanos.TenantLabel,
			operator,
			strings.Join(allowedTenantLabelValues, "|"))
		log.Trace().Str("function", "enforcer").Str("default query", query).Msg("")
	}

	expr, err := parser.ParseExpr(query)
	if err != nil {
		log.Warn().Msg("Failed to parse query.")
		return "", &PromQLError{err}
	}

	extractedLabelInfo, err := extractPromTenantValues(expr, config.Thanos.TenantLabel)
	if err != nil {
		log.Warn().Msg("The query cannot be handled because of a problem with tenant label values and/or operators.")
		return "", &PromQLError{err}
	}

	processedLabelInfo, err := processLabelValues(extractedLabelInfo, allowedTenantLabelValues, config.Thanos.ErrorOnIllegalTenantValue)
	if err != nil {
		log.Warn().Msg("Unable to process the label values.")
		return "", &PromQLError{err}
	}

	enforceQuery(config.Thanos.TenantLabel, processedLabelInfo, expr)

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

// enforceQuery goes through the elements of the query and sends the selectors onwards for label enforcement
func enforceQuery(tenantLabelName string, processedLabelInfo *LabelValueInfo, expr parser.Node) {
	parser.Inspect(expr, func(node parser.Node, path []parser.Node) error {

		switch n := node.(type) {
		case *parser.MatrixSelector:
			if vs, ok := n.VectorSelector.(*parser.VectorSelector); ok {
				vs.LabelMatchers = enforceMatchers(tenantLabelName, processedLabelInfo, vs.LabelMatchers)
			} else {
				// unclear how relevant this is, but we should probably complain if it were to happen
				log.Warn().Msg("Failed to get a VectorSelector from the MatrixSelector.")
			}

		case *parser.VectorSelector:
			// n.Name
			n.LabelMatchers = enforceMatchers(tenantLabelName, processedLabelInfo, n.LabelMatchers)

		}

		return nil
	})
}

// enforceMatchers examines the matchers in the given selector, and replaces any for our tenant label with our chosen value
func enforceMatchers(tenantLabelName string, processedLabelInfo *LabelValueInfo, toCheck []*labels.Matcher) []*labels.Matcher {
	var res []*labels.Matcher

	for _, oneExistingMatcher := range toCheck {
		if oneExistingMatcher.Name != tenantLabelName {
			res = append(res, oneExistingMatcher)
		}
	}

	res = append(res, &labels.Matcher{
		Name:  tenantLabelName,
		Type:  processedLabelInfo.Type,
		Value: processedLabelInfo.Value,
	})

	return res
}
