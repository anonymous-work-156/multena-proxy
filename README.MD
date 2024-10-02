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

This is a fork to meet some internal requirements, see the [upstream repo](https://github.com/gepaplexx/multena-proxy) for a proper world view.

Our changes (at the time of this writing) are basically:
1.  Configure the HTTP header in which the JWT arrives
2.  Allow the HTTP header value to not start with "BEARER"
3.  Configure the sub-paths at which Loki and Promethues are proxied
4.  Support the four operators `==`, `!=`, `=~` and `!~` for tenant labels *(currently for the metrics proxy)*
5.  Support arbitrary regex syntax for tenant label values *(currently for the metrics proxy)*
6.  Configure the behavior when an illegal or non-matching tenant label value is specified (error vs match empty string) *(currently for the metrics proxy)*
7.  Extended test cases
8.  Rename some variables
9.  Rephrase some error messages