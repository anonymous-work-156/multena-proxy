package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

func Test_reverseProxy(t *testing.T) {

	appmap, tokens := setupReverseProxyTest()

	type ExpectedResult struct {
		matchingApp string
		status      int
		body        string
	}

	type TestHeader struct {
		key string
		val string
	}

	type TestCase struct {
		name                string
		baseName            string
		URL                 string
		noSetAuthorization  bool
		authorizationHeader string
		header              TestHeader
		expectedResults     []ExpectedResult
	}

	cases := []TestCase{
		{
			baseName: "wrong_path",
			URL:      "/foo/bar",
			expectedResults: []ExpectedResult{{
				matchingApp: "*",
				status:      http.StatusNotFound,
				body:        "not a registered route\n", // we hope to hit our logEverythingElseHandler
			}},
		},
		{
			baseName:            "crap_request",
			URL:                 "/api/v1/query?bar=&=bad",        // should trigger the regex check in the test server
			authorizationHeader: "Bearer " + tokens["userTenant"], // valid creds
			expectedResults: []ExpectedResult{{
				matchingApp: "*",
				status:      http.StatusBadRequest, // test that our test server rejects this and that we can observe the rejection
				body:        "Bad Parameters",
			}},
		},
		{
			baseName:           "no_headers_at_all",
			URL:                "/api/v1/query_range",
			noSetAuthorization: true,
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusForbidden,
					body:        "got no value for the HTTP header which is expected to contain the JWT\n",
				},
			},
		},
		{
			baseName:           "missing_auth_header",
			URL:                "/api/v1/query_range",
			noSetAuthorization: true,
			header:             TestHeader{key: "MagicHeader", val: "notaverygoodsecret"}, // one app should pass due to this
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusForbidden,
					body:        "got no value for the HTTP header which is expected to contain the JWT\n",
				},
				{
					matchingApp: "group_or_header",
					status:      http.StatusOK,
					body:        "Query string did not contain parameters.\n",
				},
			},
		},
		{
			baseName:            "malformed_auth_header_1",
			URL:                 "/api/v1/query_range",
			authorizationHeader: "B",
			header:              TestHeader{key: "MagicHeader", val: "notaverygoodsecret"}, // one app should pass due to this
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusForbidden,
					body:        "failed to remove the bearer prefix from the JWT\n",
				},
				{
					matchingApp: "group_or_header",
					status:      http.StatusOK,
					body:        "Query string did not contain parameters.\n",
				},
			},
		},
		{
			baseName:            "malformed_auth_header_2",
			URL:                 "/api/v1/query_range",
			authorizationHeader: "Bearer ",
			header:              TestHeader{key: "MagicHeader", val: "notaverygoodsecret"}, // one app should pass due to this
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusForbidden,
					body:        "error parsing token\n",
				},
				{
					matchingApp: "group_or_header",
					status:      http.StatusOK,
					body:        "Query string did not contain parameters.\n",
				},
			},
		},
		{
			baseName:            "malformed_headers_1",
			URL:                 "/api/v1/query_range",
			authorizationHeader: "Bearer skk",
			header:              TestHeader{key: "MagicHeader", val: "wrong"},
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusForbidden,
					body:        "error parsing token\n",
				},
			},
		},
		{
			baseName:            "malformed_headers_2",
			URL:                 "/api/v1/query_range",
			authorizationHeader: "Bearer abc def",
			header:              TestHeader{key: "MagicHeader", val: ""},
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusForbidden,
					body:        "error parsing token\n",
				},
			},
		},
		{
			baseName:            "user_in_token_is_invalid_1",
			URL:                 "/api/v1/query_range",
			authorizationHeader: "Bearer " + tokens["invalidTenant"],                       // token configured with user name which is not in config store
			header:              TestHeader{key: "MagicHeader", val: "notaverygoodsecret"}, // one app should pass due to this
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusForbidden,
					body:        "no tenant labels are configured for the user\n",
				},
				{
					matchingApp: "group_or_header",
					status:      http.StatusOK,
					body:        "Query string did not contain parameters.\n",
				},
			},
		},
		{
			baseName:            "user_in_token_is_invalid_2",
			URL:                 `/api/v1/query_range?query=up{tenant_id="forbidden_tenant"}`, // there is no value for tenant_id that should work
			authorizationHeader: "Bearer " + tokens["invalidTenant"],                          // token configured with user name which is not in config store
			header:              TestHeader{key: "MagicHeader", val: "notaverygoodsecret"},    // one app should pass due to this
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusForbidden,
					body:        "no tenant labels are configured for the user\n",
				},
				{
					matchingApp: "group_or_header",
					status:      http.StatusOK,
					body:        "Query string parameter keys: query\n",
				},
			},
		},
		{
			baseName:            "empty_query",
			URL:                 `/api/v1/query_range`,
			authorizationHeader: "Bearer " + tokens["userTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "Query string parameter keys: query\n",
				},
			},
		},
		{
			baseName:            "multiple_group_membership_with_invalid_tenant",
			URL:                 `/api/v1/query_range?query=up{tenant_id="forbidden_tenant"}`,
			authorizationHeader: "Bearer " + tokens["groupTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "Query string parameter keys: query\n",
				},
				{
					matchingApp: "bad_tenant_intolerant",
					status:      http.StatusForbidden,
					body:        `{"status":"error","errorType":"bad_data","error": "unauthorized tenant label value"}` + "\n",
				},
			},
		},
		{
			baseName:            "user_without_groups_with_invalid_tenant",
			URL:                 `/api/v1/query?query=up{tenant_id="another_forbidden_tenant"}`,
			authorizationHeader: "Bearer " + tokens["userTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "Query string parameter keys: query\n",
				},
				{
					matchingApp: "bad_tenant_intolerant",
					status:      http.StatusForbidden,
					body:        `{"status":"error","errorType":"bad_data","error": "unauthorized tenant label value"}` + "\n",
				},
			},
		},
		{
			baseName:            "user_query_that_results_in_no_matched_tenant_label_values_and_empty_result",
			URL:                 `/api/v1/query?query=up{tenant_id=~"frogs!"}`,
			authorizationHeader: "Bearer " + tokens["userTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "Query string parameter keys: query\n",
				},
				{
					matchingApp: "bad_tenant_intolerant",
					status:      http.StatusForbidden,
					body:        `{"status":"error","errorType":"bad_data","error": "no tenant label values matched"}` + "\n",
				},
			},
		},
		{
			baseName:            "group_membership_with_single_valid_tenant_value",
			URL:                 `/api/v1/query?query=up{tenant_id="tenant_id_g1"}`,
			authorizationHeader: "Bearer " + tokens["groupTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "Query string parameter keys: query\n",
				},
			},
		},
		{
			baseName:            "multiple_group_membership_with_single_valid_tenant_value",
			URL:                 `/api/v1/query?query={tenant_id="tenant_id_g2"} != 1337`,
			authorizationHeader: "Bearer " + tokens["twoGroupsTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "Query string parameter keys: query\n",
				},
			},
		},
		{
			baseName:            "multiple_group_membership_with_multiple_valid_tenant_values_1",
			URL:                 `/api/v1/query?query=up{tenant_id=~"tenant_id_g1|tenant_id_g4"}`,
			authorizationHeader: "Bearer " + tokens["twoGroupsTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "Query string parameter keys: query\n",
				},
			},
		},
		{
			baseName:            "multiple_group_membership_with_multiple_valid_tenant_values_2",
			URL:                 `/api/v1/query?query={tenant_id=~"tenant_id_g1|tenant_id_g3"} != 1337`,
			authorizationHeader: "Bearer " + tokens["twoGroupsTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "Query string parameter keys: query\n",
				},
			},
		},
		{
			baseName:            "admin_bypass_from_config",
			URL:                 `/api/v1/query?query=some_metric{tenant_id="whocaresweretheadmin"} != 1337`,
			authorizationHeader: "Bearer " + tokens["adminBypassTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "Query string parameter keys: query\n",
				},
				{
					matchingApp: "only_magic_val",
					status:      http.StatusForbidden,
					body:        "no tenant labels are configured for the user\n",
				},
			},
		},
		{
			baseName:            "admin_bypass_from_nested_labelstore",
			URL:                 `/api/v1/query?query=some_metric{tenant_id="whocaresweretheadmin"} != 1337`,
			authorizationHeader: "Bearer " + tokens["nestedBypassTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusForbidden,
					body:        "no tenant labels are configured for the user\n",
				},
				{
					matchingApp: "bad_tenant_tolerant_nested",
					status:      http.StatusOK,
					body:        "Query string parameter keys: query\n",
				},
			},
		},
		{
			baseName:            "strange_query_with_magic_value_bypass_1",
			URL:                 `/api/v1/query?query=count(count({__name__!="",tenant_id="bob"}) by (__name__))`, // any tenant value works
			authorizationHeader: "Bearer " + tokens["magicBypassTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "Query string parameter keys: query\n",
				},
				{
					matchingApp: "bad_tenant_intolerant",
					status:      http.StatusForbidden,
					body:        `{"status":"error","errorType":"bad_data","error": "unauthorized tenant label value"}` + "\n",
				},
				{
					matchingApp: "bad_tenant_tolerant_nested",
					status:      http.StatusForbidden,
					body:        "no tenant labels are configured for the user\n",
				},
			},
		},
		{
			baseName:            "strange_query_with_magic_value_bypass_2",
			URL:                 `/api/v1/query?query=count(count({__name__!=""}) by (__name__))`, // missing tenant value works
			authorizationHeader: "Bearer " + tokens["magicBypassTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "Query string parameter keys: query\n",
				},
				{
					matchingApp: "bad_tenant_tolerant_nested",
					status:      http.StatusForbidden,
					body:        "no tenant labels are configured for the user\n",
				},
			},
		},
		{
			baseName:            "strange_query_with_magic_value_bypass_3",
			URL:                 `/api/v1/query?query=count(count({__name__!="",tenant_id="bob"}) by (__name__))`, // without the magic value, tenant is checked
			authorizationHeader: "Bearer " + tokens["twoGroupsTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "Query string parameter keys: query\n",
				},
				{
					matchingApp: "bad_tenant_intolerant",
					status:      http.StatusForbidden,
					body:        `{"status":"error","errorType":"bad_data","error": "unauthorized tenant label value"}` + "\n",
				},
			},
		},
		{
			baseName:            "invalid_magic_value_bypass",
			URL:                 `/api/v1/query?query=count(count({__name__!="",tenant_id="bob"}) by (__name__))`, // without the magic value, tenant is checked
			authorizationHeader: "Bearer " + tokens["invalidMagicBypassTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusForbidden,
					body:        "no tenant labels are configured for the user\n",
				},
			},
		},
		{
			baseName:            "invalid_magic_value_bypass_with_magic_header",
			URL:                 `/api/v1/query?query=count(count({__name__!="",tenant_id="bob"}) by (__name__))`, // without the magic value, tenant is checked
			authorizationHeader: "Bearer " + tokens["invalidMagicBypassTenant"],
			header:              TestHeader{key: "MagicHeader", val: "notaverygoodsecret"},
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusForbidden,
					body:        "no tenant labels are configured for the user\n",
				},
				{
					matchingApp: "group_or_header",
					status:      http.StatusOK,
					body:        "Query string parameter keys: query\n",
				},
			},
		},
		{
			baseName:            "loki_queryrange_with_valid_label",
			URL:                 "/loki/api/v1/query_range?direction=backward&end=1690463973787000000&limit=1000&query=sum by (level) (count_over_time({tenant_id=\"tenant_id_g1\"} |= `path` |= `label` | json | line_format `{{.message}}` | json | line_format `{{.request}}` | json | line_format `{{.method | printf \"%-4s\"}} {{.path | printf \"%-60s\"}} {{.url | urldecode}}`[1m]))&start=1690377573787000000&step=60000ms",
			authorizationHeader: "Bearer " + tokens["twoGroupsTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "Query string parameter keys: direction,end,limit,query,start,step\n",
				},
			},
		},
		{
			baseName:            "loki_index_stats_with_valid_label",
			URL:                 `/loki/api/v1/index/stats?query={tenant_id="tenant_id_u1"}&start=1690377573724000000&end=1690463973724000000`,
			authorizationHeader: "Bearer " + tokens["userTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "Query string parameter keys: end,query,start\n",
				},
			},
		},
		{
			baseName:            "loki_big_query_invalid_label_1",
			URL:                 "/loki/api/v1/query_range?direction=backward&end=1690463973693000000&limit=10&query={tenant_id=\"forbidden_tenant\"} |= `path` |= `label` | json | line_format `{{.message}}` | json | line_format `{{.request}}` | json | line_format `{{.method}} {{.path}} {{.url | urldecode}}`&start=1690377573693000000&step=86400000ms",
			authorizationHeader: "Bearer " + tokens["userAndGroupTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "Query string parameter keys: direction,end,limit,query,start,step\n",
				},
				{
					matchingApp: "bad_tenant_intolerant",
					status:      http.StatusForbidden,
					body:        "unauthorized tenant label value\n",
				},
			},
		},
		{
			baseName:            "loki_big_query_invalid_label_2",
			URL:                 `/loki/api/v1/query_range?direction=backward&end=1690463973693000000&limit=10&query={tenant_id="forbidden_tenant"}`,
			authorizationHeader: "Bearer " + tokens["userTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "Query string parameter keys: direction,end,limit,query\n",
				},
				{
					matchingApp: "bad_tenant_intolerant",
					status:      http.StatusForbidden,
					body:        "unauthorized tenant label value\n",
				},
			},
		},
		{
			baseName:            "loki_big_query_invalid_label_3",
			URL:                 `/loki/api/v1/query_range?direction=backward&end=1690463973693000000&limit=10&query={tenant_id="forbidden_tenant"}`,
			authorizationHeader: "Bearer " + tokens["magicBypassTenant"],
			expectedResults: []ExpectedResult{
				{
					matchingApp: "*",
					status:      http.StatusOK,
					body:        "Query string parameter keys: direction,end,limit,query\n",
				},
				{
					matchingApp: "bad_tenant_intolerant",
					status:      http.StatusForbidden,
					body:        "unauthorized tenant label value\n",
				},
				{
					matchingApp: "bad_tenant_tolerant_nested",
					status:      http.StatusForbidden,
					body:        "no tenant labels are configured for the user\n",
				},
			},
		},
	}

	for appname, app := range appmap {
		for _, tc := range cases {
			tc.name = tc.baseName + "/" + appname
			t.Run(tc.name, func(t *testing.T) {

				// Create a request
				log.Debug().Str("URL", tc.URL).Str("Authorization", tc.authorizationHeader).Msg("Test request")
				req, err := http.NewRequest("GET", tc.URL, nil)
				if err != nil {
					t.Fatal(err)
				}

				// Set headers based on the test case.
				if !tc.noSetAuthorization {
					req.Header.Add("Authorization", tc.authorizationHeader)
				}
				if tc.header.key != "" {
					req.Header.Add(tc.header.key, tc.header.val)
				}

				// Prepare the response recorder
				rr := httptest.NewRecorder()

				// Call the function
				app.e.ServeHTTP(rr, req)

				// Find which of the expected results applies to our situation
				expectedResults := ExpectedResult{}
				for _, maybe := range tc.expectedResults {
					if maybe.matchingApp == appname {
						expectedResults = maybe
					}
				}
				if expectedResults.matchingApp == "" {
					for _, maybe := range tc.expectedResults {
						if maybe.matchingApp == "*" {
							expectedResults = maybe
						}
					}
				}
				log.Info().Str("Testcase result matcher", expectedResults.matchingApp).Msg("")

				// Check the status code and body
				happy := assert.Equal(t, expectedResults.status, rr.Code)
				happy = happy && assert.Equal(t, expectedResults.body, rr.Body.String())

				log.Info().Bool("passed", happy).Str("name", tc.name).Str("appname", appname).Msg("Reverse proxy test")
			})
		}
	}
}

func TestIsAdminSkip(t *testing.T) {
	a := assert.New(t)

	app := &App{}
	app.WithConfig()
	app.Cfg.Admin.GroupBypass = true
	app.Cfg.Admin.Group = "gepardec-run-admins"

	token := &OAuthToken{Groups: []string{"gepardec-run-admins"}}
	a.True(isAdmin(*token, app))
	app.Cfg.Admin.GroupBypass = false // show that we need group bypass to be enabled
	a.False(isAdmin(*token, app))

	app.Cfg.Admin.GroupBypass = true
	token.Groups = []string{"usergroup"} // not admin group
	a.False(isAdmin(*token, app))
	app.Cfg.Admin.GroupBypass = false
	a.False(isAdmin(*token, app))

	app.Cfg.Admin.GroupBypass = true
	token.Groups = []string{"gepardec-run-admins", "g2", "g3"}
	a.True(isAdmin(*token, app))
}

func TestLogAndWriteError(t *testing.T) {
	a := assert.New(t)

	rw := httptest.NewRecorder()
	logAndWriteError(rw, http.StatusInternalServerError, nil, "test error")
	a.Equal(http.StatusInternalServerError, rw.Code)
	a.Equal("test error\n", rw.Body.String())
}
