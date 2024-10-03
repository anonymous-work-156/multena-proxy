package main

import (
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/rs/zerolog/log"

	logqlv2 "github.com/observatorium/api/logql/v2"
	"github.com/prometheus/prometheus/model/labels"
)

// LogQLEnforcer manipulates and enforces tenant isolation on LogQL queries.
type LogQLEnforcer struct{}

// Enforce modifies a LogQL query string to enforce tenant isolation based on provided tenant labels and a label match string.
// If the input query is empty, a new query is constructed to match provided tenant labels.
// If the input query is non-empty, it is parsed and modified to ensure tenant isolation.
// Returns the modified query or an error if parsing or modification fails.
func (LogQLEnforcer) Enforce(query string, allowedTenantLabelValues []string, tenantLabelName string, errorOnIllegalTenantValue bool) (string, error) {
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

	expr, err := logqlv2.ParseExpr(query)
	if err != nil {
		return "", err
	}

	extractedLabelInfo, err := extractLokiTenantValues(expr, tenantLabelName)
	if err != nil {
		log.Warn().Msg("The query cannot be handled because of a problem with tenant label values and/or operators.")
		return "", err
	}

	processedLabelInfo, err := processLabelValues(extractedLabelInfo, allowedTenantLabelValues, errorOnIllegalTenantValue)
	if err != nil {
		log.Warn().Msg("Unable to process the label values.")
		return "", err
	}

	setLokiTenantValues(expr, tenantLabelName, processedLabelInfo)

	log.Trace().Str("function", "enforcer").Str("query", expr.String()).Msg("enforcing")
	return expr.String(), nil
}

// extractLokiTenantValues parses a PromQL expression and extracts labels and their values.
// Returns a struct containing the operator and tenant label value which were found.
// An error is returned if conflicting operator and/or values are found for the tenant label.
// NOTE: It is crude to insist that only one distinct operator and value are associated with the tenant label; it forbids some valid queries.
func extractLokiTenantValues(expr logqlv2.Expr, tenantLabelName string) (*LabelValueInfo, error) {
	var info map[LabelValueInfo]bool = make(map[LabelValueInfo]bool)
	expr.Walk(func(expr interface{}) {
		switch labelExpression := expr.(type) {
		case *logqlv2.StreamMatcherExpr:
			for _, matcher := range labelExpression.Matchers() {
				if matcher.Name != tenantLabelName {
					continue
				}
				thisinfo := LabelValueInfo{matcher.Value, matcher.Type}
				_, ok := info[thisinfo]
				if !ok {
					info[thisinfo] = true
				}
			}
		default:
			// Do nothing
		}
	})
	if len(info) == 1 {
		for v := range maps.Keys(info) {
			// WTF Go, is this the best way?
			return &v, nil
		}
	}
	if len(info) > 1 {
		return nil, errors.New("found conflicting values or operators for tenant label")
	}
	return nil, nil
}

// setLokiTenantValues ensures tenant label matchers in a LogQL query adhere to provided tenant labels.
// It verifies that the tenant label exists in the query matchers, validating or modifying its values based on tenantLabels.
func setLokiTenantValues(expr logqlv2.Expr, tenantLabelName string, processedLabelInfo *LabelValueInfo) {
	expr.Walk(func(expr interface{}) {
		switch labelExpression := expr.(type) {
		case *logqlv2.StreamMatcherExpr:
			matchers := make([]*labels.Matcher, 0)
			for _, matcher := range labelExpression.Matchers() {
				if matcher.Name != tenantLabelName {
					matchers = append(matchers, matcher)
				}
			}

			matchers = append(matchers, &labels.Matcher{
				Type:  processedLabelInfo.Type,
				Name:  tenantLabelName,
				Value: processedLabelInfo.Value,
			})

			labelExpression.SetMatchers(matchers)
		default:
			// Do nothing
		}
	})
}
