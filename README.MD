# Multena Proxy

Making the LGTM-Stack **mul**ti **tena**ncy ready.

---
**Multena Proxy** is a multi-tenancy ready tool designed to enhance the authorization capabilities of your LGTM (Loki
Grafana Tempo Mimir(Prometheus Style API / OpenMetrics)) stack. Built with LBAC (Label Based Access Control) at its
core.

Multena provides secure and granular user authorization based on assigned tenant labels.
It integrates seamlessly with PrometheusAPI and Loki, and
should support generic oauth provider for identity management. With features like ConfigMap-based configuration,
flexible authorization providers, and multiple tenant labels, Multena ensures that the right data is accessible to the
right users.

# Forked

This is a fork to meet some (expanding) internal requirements, see the [upstream repo](https://github.com/gepaplexx/multena-proxy) for a proper world view.

Our changes (at the time of this writing) are basically:
1.  Configure the HTTP header in which the JWT arrives
2.  Allow the HTTP header value to not start with "BEARER"
3.  Configure the sub-paths at which Loki and Promethues are proxied
4.  Support the four operators `==`, `!=`, `=~` and `!~` for tenant labels (including regex syntax)
5.  Allow different tenant label matchers in different selectors in the same query
6.  Configure the behavior when an illegal or non-matching tenant label value is specified (error vs impossible match)
7.  PromQL only: allow the tenant label to be an empty string (missing) for specially configured metrics
8.  Extended test cases
9.  Rephrase and reformat some error messages

As time has passed, an notable percentage of the total code has been replaced.