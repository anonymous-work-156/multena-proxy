package main

import (
	"fmt"
	"slices"
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

	err = enforcePromQuery(config, allowedTenantLabelValues, expr)
	if err != nil {
		return "", &PromQLError{err}
	}

	log.Trace().Str("function", "enforcer").Str("approved query", expr.String()).Msg("")
	log.Trace().Msg("Returning approved expression.")
	return expr.String(), nil
}

// enforcePromQuery goes through the elements of the query and sends the selectors onwards for label enforcement
func enforcePromQuery(config *Config, allowedTenantLabelValues []string, expr parser.Node) error {
	var errs []error = make([]error, 0)

	parser.Inspect(expr, func(node parser.Node, path []parser.Node) error {
		var err error

		// we are only processing VectorSelector (note that MatrixSelector contains a VectorSelector which will also be visited by this function)
		if n, ok := node.(*parser.VectorSelector); ok {

			// for some metrics we allow there to be no value for the tenant label (i.e. "") even if that is not granted to the user/group in question
			allowMissingTenant := slices.Contains(config.Thanos.UnfilteredMetrics, n.Name)

			n.LabelMatchers, err = enforcePromMatchers(config.Thanos.TenantLabel, config.Thanos.ErrorOnIllegalTenantValue, allowMissingTenant, allowedTenantLabelValues, n.LabelMatchers)
			if err != nil {
				errs = append(errs, err)
			}
		}

		return nil
	})

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// enforcePromMatchers examines the matchers in the given selector, and replaces any for our tenant label with our chosen value
func enforcePromMatchers(tenantLabelName string, errorOnIllegalTenantValue bool, allowMissingTenant bool, allowedTenantLabelValues []string, originalMatchers []*labels.Matcher) ([]*labels.Matcher, error) {
	var matchersFound []*labels.Matcher
	var extractedLabelInfo *LabelValueInfo
	var res []*labels.Matcher

	// scan the list of matches, keep those which are not our tenant label without modification
	// find matches on our tenant label, ensure that if there is more than one, that they are identical
	for _, matcher := range originalMatchers {
		log.Info().Str("name", matcher.Name).Msg("found a matcher")
		if matcher.Name != tenantLabelName {
			matchersFound = append(matchersFound, matcher)
		} else {
			// record the operator and value for our tenant label, ensure that if there are more than one, they are identical (i.e. redundant)
			// we do not currently support multiple matchers for the tenant label even when they would be valid
			var found = LabelValueInfo{matcher.Value, matcher.Type}
			if extractedLabelInfo != nil && *extractedLabelInfo != found {
				return nil, ErrMultipleValOrOper
			}
			extractedLabelInfo = &found
		}
	}

	// sometimes we allow there to be no value for the tenant label (i.e. "") even if that is not granted to the user/group in question
	// TODO: unsure if this effects the data that the original slice contains
	if allowMissingTenant && !slices.Contains(allowedTenantLabelValues, "") {
		allowedTenantLabelValues = append(allowedTenantLabelValues, "")
	}

	// convert any tenant label found in context of the allowed values
	processedLabelInfo, err := processLabelValues(extractedLabelInfo, allowedTenantLabelValues)

	if err != nil {
		if !errorOnIllegalTenantValue && (err == ErrUnauthorizedLabelValue || err == ErrNoLabelMatch) {
			// we continue without an error, but insert conflicting matchers to ensure there is no result
			// the user has either tried to use a forbidden tenant label value, or specified a value and operator that leads to no matches with allowed values
			res = append(matchersFound, &labels.Matcher{
				Name:  tenantLabelName,
				Type:  labels.MatchEqual,
				Value: "",
			})
			res = append(res, &labels.Matcher{
				Name:  tenantLabelName,
				Type:  labels.MatchNotEqual,
				Value: "",
			})
		} else {
			log.Warn().Msg("Unable to process the label values.")
			return nil, err
		}
	} else {
		// normal happy case where we attach one matcher
		res = append(matchersFound, &labels.Matcher{
			Name:  tenantLabelName,
			Type:  processedLabelInfo.Type,
			Value: processedLabelInfo.Value,
		})
	}

	return res, nil
}
