package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/prometheus/prometheus/model/labels" // it seems PromQL and LogQL code both refer to the prom operator defintion, handy!
)

type LabelValueInfo struct {
	Value string
	Type  labels.MatchType
}

func (c LabelValueInfo) String() string {
	return fmt.Sprintf("LabelValueInfo(%v %v)", c.Type, c.Value)
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
				return nil, fmt.Errorf("unsupported operator")
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
		return nil, fmt.Errorf("no tenant label values matched")
	}

	// zero matches requires matching the empty string
	return &LabelValueInfo{"", labels.MatchEqual}, nil
}
