package main

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"

	enforcer "github.com/prometheus-community/prom-label-proxy/injectproxy"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

type LabelValueInfo struct {
	Value string
	Type  labels.MatchType
}

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
		return "", err
	}

	extractedLabelInfo, err := extractTenantValues(expr, tenantLabelName)
	if err != nil {
		log.Warn().Msg("The query cannot be handled because of a problem with tenant label values and/or operators.")
		return "", err
	}

	processedLabelInfo, err := processLabelValues(extractedLabelInfo, allowedTenantLabelValues, errorOnIllegalTenantValue)
	if err != nil {
		log.Warn().Msg("Unable to process the label values.")
		return "", err
	}

	labelEnforcer := enforcer.NewPromQLEnforcer(false, &labels.Matcher{
		Name:  tenantLabelName,
		Type:  processedLabelInfo.Type,
		Value: processedLabelInfo.Value,
	})

	err = labelEnforcer.EnforceNode(expr)
	if err != nil {
		log.Warn().Msg("The promql label enforcer was unhappy.")
		return "", err
	}
	log.Trace().Str("function", "enforcer").Str("approved query", expr.String()).Msg("")
	log.Trace().Msg("Returning approved expression.")
	return expr.String(), nil
}

// extractTenantValues parses a PromQL expression and extracts labels and their values.
// It returns a struct containing the operator and tenant label value which were found.
// An error is returned if the expression cannot be parsed, or if conflicting operator and/or values are found for the tenant label.
func extractTenantValues(expr parser.Expr, tenantLabelName string) (*LabelValueInfo, error) {
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
		return nil, errors.New("found conflicting values or operators for tenant label")
	}
	return nil, nil
}

// processLabelValues takes the tenant label operator and value that were found (if any) and creates a new operator and tenant label value from them.
// The new operator and value may be the same, or they may reflect simplifications from evaluating the operator and value in context of the allowed values.
// An error can be returned (depending on errorOnIllegalTenantValue) if the tenant label value is illegal or matches nothing.
func processLabelValues(extractedLabelInfo *LabelValueInfo, allowedTenantLabelValues []string, errorOnIllegalTenantValue bool) (*LabelValueInfo, error) {

	// when no tenant label has been provided by the client
	if extractedLabelInfo == nil {
		if len(allowedTenantLabelValues) == 1 {
			return &LabelValueInfo{allowedTenantLabelValues[0], labels.MatchEqual}, nil
		}
		if len(allowedTenantLabelValues) == 0 {
			return &LabelValueInfo{"", labels.MatchEqual}, nil
		}

		// all the allowed values in one regex
		val := strings.Join(allowedTenantLabelValues, "|")
		return &LabelValueInfo{val, labels.MatchRegexp}, nil
	}

	if extractedLabelInfo.Type == labels.MatchEqual {
		// equal one of the allowed values
		if slices.Contains(allowedTenantLabelValues, extractedLabelInfo.Value) {
			return extractedLabelInfo, nil
		} else if errorOnIllegalTenantValue {
			return nil, fmt.Errorf("unauthorized tenant label value %s", extractedLabelInfo.Value)
		}
	} else {

		var toInclude []string
		if extractedLabelInfo.Type == labels.MatchNotEqual {

			// match all of the allowed values except possibly one of them
			for _, val := range allowedTenantLabelValues {
				if val != extractedLabelInfo.Value {
					toInclude = append(toInclude, val)
				}
			}

		} else {
			rx, err := labels.NewFastRegexMatcher(extractedLabelInfo.Value)
			if err != nil {
				return nil, err
			}

			var want bool
			if extractedLabelInfo.Type == labels.MatchRegexp {
				// whatever of the values match the regex
				want = true
			} else if extractedLabelInfo.Type == labels.MatchNotRegexp {
				// whatever of the values do not match the regex
				want = false
			} else {
				// FIXME: this is probably not the proper way to handle the situation
				return nil, errors.New("unsupported operator")
			}

			for _, val := range allowedTenantLabelValues {
				if rx.MatchString(val) == want {
					toInclude = append(toInclude, val)
				}
			}
		}

		if len(toInclude) == 1 {
			// one value to match can be handled without regex
			return &LabelValueInfo{toInclude[0], labels.MatchEqual}, nil
		}
		if len(toInclude) > 0 {
			// multi-matches requires a regex
			val := strings.Join(toInclude, "|")
			return &LabelValueInfo{val, labels.MatchRegexp}, nil
		}
	}

	if errorOnIllegalTenantValue {
		// FIXME: maybe improve the error message
		return nil, errors.New("no tenant labels found")
	}

	// zero matches requires matching the empty string
	return &LabelValueInfo{"", labels.MatchEqual}, nil
}
