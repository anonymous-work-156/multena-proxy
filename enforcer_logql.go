package main

import (
	"fmt"
	"strings"

	logqlv3 "github.com/grafana/loki/v3/pkg/logql/syntax"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/rs/zerolog/log"
)

// LogQLEnforcer manipulates and enforces tenant isolation on LogQL queries.
type LogQLEnforcer struct{}

// Enforce modifies a LogQL query string to enforce tenant isolation based on provided tenant labels and a label match string.
// If the input query is empty, a new query is constructed to match provided tenant labels.
// If the input query is non-empty, it is parsed and modified to ensure tenant isolation.
// Returns the modified query or an error if parsing or modification fails.
func (LogQLEnforcer) Enforce(query string, allowedTenantLabelValues []string, config *Config) (string, error) {
	log.Trace().Str("function", "enforcer").Str("input query", query).Msg("")

	if query == "" {
		operator := "="
		if len(allowedTenantLabelValues) > 1 {
			operator = "=~"
		}
		query = fmt.Sprintf("{%s%s\"%s\"}",
			config.Loki.TenantLabel,
			operator,
			strings.Join(allowedTenantLabelValues, "|"))
		log.Trace().Str("function", "enforcer").Str("default query", query).Msg("")
	}

	expr, err := logqlv3.ParseExpr(query)
	if err != nil {
		return "", err
	}

	err = enforceLogQuery(expr, config.Loki.TenantLabel, config.Loki.ErrorOnIllegalTenantValue, allowedTenantLabelValues)
	if err != nil {
		return "", err
	}

	log.Trace().Str("function", "enforcer").Str("query", expr.String()).Msg("enforcing")
	return expr.String(), nil
}

// enforceLogQuery ensures tenant label matchers in a LogQL query adhere to provided tenant labels.
// It verifies that the tenant label exists in the query matchers, validating or modifying its values based on tenantLabels.
func enforceLogQuery(expr logqlv3.Expr, tenantLabelName string, errorOnIllegalTenantValue bool, allowedTenantLabelValues []string) error {
	var errs []error = make([]error, 0)

	expr.Walk(func(expr2 logqlv3.Expr) {
		matcherExpr, ok := expr2.(*logqlv3.MatchersExpr)
		if !ok {
			return // we are only looking for MatchersExpr
		}

		err := enforceLogMatchers(tenantLabelName, errorOnIllegalTenantValue, allowedTenantLabelValues, matcherExpr)
		if err != nil {
			errs = append(errs, err)
		}
	})

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// enforceLogMatchers examines the matchers in the given selector, and replaces any for our tenant label with our chosen value
func enforceLogMatchers(tenantLabelName string, errorOnIllegalTenantValue bool, allowedTenantLabelValues []string, matcherExpr *logqlv3.MatchersExpr) error {
	var extractedLabelInfo *LabelValueInfo

	// scan the list of matches, find matches on our tenant label, ensure that if there is more than one, that they are identical
	for _, matcher := range matcherExpr.Matchers() {
		if matcher.Name == tenantLabelName {
			// record the operator and value for our tenant label, ensure that if there are more than one, they are identical (i.e. redundant)
			// we do not currently support multiple matchers for the tenant label even when they would be valid
			var found = LabelValueInfo{matcher.Value, matcher.Type}
			if extractedLabelInfo != nil && *extractedLabelInfo != found {
				return ErrMultipleValOrOper
			}
			extractedLabelInfo = &found
		}
	}

	// convert any tenant label found in context of the allowed values
	processedLabelInfo, err := processLabelValues(extractedLabelInfo, allowedTenantLabelValues)

	if err != nil {
		if !errorOnIllegalTenantValue && (err == ErrUnauthorizedLabelValue || err == ErrNoLabelMatch) {
			// we continue without an error, but insert conflicting matchers to ensure there is no result
			// the user has either tried to use a forbidden tenant label value, or specified a value and operator that leads to no matches with allowed values
			disableLogMatcherExpr(tenantLabelName, matcherExpr)
		} else {
			log.Warn().Msg("Unable to process the label values.")
			return err
		}
	} else {
		attachGoodMatcher(processedLabelInfo, tenantLabelName, matcherExpr)
	}

	return nil
}

func disableLogMatcherExpr(tenantLabelName string, matcherExpr *logqlv3.MatchersExpr) {
	cnt := 0

	// first, try to replace any matchers that already exist
	// this is not strictly necessary, but the resulting query will be cleaner
	matchers := matcherExpr.Matchers()
	for idx, matcher := range matchers {
		if matcher.Name == tenantLabelName {
			op := labels.MatchEqual
			if cnt > 0 {
				op = labels.MatchNotEqual
			}
			newmatcher := &labels.Matcher{
				Type:  op,
				Name:  tenantLabelName,
				Value: "",
			}
			matchers[idx] = newmatcher
			cnt += 1
		}
	}

	// if the tenant label matcher didn't exist at all, append one
	if cnt == 0 {
		appendme := []*labels.Matcher{{
			Type:  labels.MatchEqual,
			Name:  tenantLabelName,
			Value: "",
		}}
		matcherExpr.AppendMatchers(appendme)
		cnt += 1
	}

	// if only one copy of the tenant label matcher is defined so far, attach another one
	if cnt == 1 {
		appendme := []*labels.Matcher{{
			Type:  labels.MatchNotEqual,
			Name:  tenantLabelName,
			Value: "",
		}}
		matcherExpr.AppendMatchers(appendme)
	}
}

func attachGoodMatcher(processedLabelInfo *LabelValueInfo, tenantLabelName string, matcherExpr *logqlv3.MatchersExpr) {
	// normal happy case where we overwrite/attach our matcher
	newmatcher := &labels.Matcher{
		Type:  processedLabelInfo.Type,
		Name:  tenantLabelName,
		Value: processedLabelInfo.Value,
	}

	found := false
	matchers := matcherExpr.Matchers()
	for idx, matcher := range matchers {
		if matcher.Name == tenantLabelName {
			matchers[idx] = newmatcher
			found = true
		}
	}

	if !found {
		appendme := []*labels.Matcher{{
			Type:  processedLabelInfo.Type,
			Name:  tenantLabelName,
			Value: processedLabelInfo.Value,
		}}
		matcherExpr.AppendMatchers(appendme)
	}
}
