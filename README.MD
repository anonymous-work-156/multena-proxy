# *(forked)* Multena Proxy *(forked)*

Making the LGTM-Stack **mul**ti **tena**ncy ready.

---
**Multena Proxy** is a multi-tenancy ready tool designed to enhance the authorization capabilities of your LGTM (Loki
Grafana Tempo Mimir(Prometheus Style API / OpenMetrics)) stack. Built with LBAC (Label Based Access Control) at its
core.

## Forked

This is a fork to meet some (expanding) internal requirements, see the [upstream repo](https://github.com/gepaplexx/multena-proxy) for a proper world view from the original authors.

Our changes (at the time of this writing) are basically:
1.  Configure the HTTP header in which the JWT arrives
2.  Allow the HTTP header value to not start with "BEARER"
3.  Configure the sub-paths at which Loki and Promethues are proxied
4.  Support the four operators `==`, `!=`, `=~` and `!~` for tenant labels (including regex syntax)
5.  Allow different tenant label matchers in different selectors in the same query
6.  Configure the behavior when an illegal or non-matching tenant label value is specified (error vs impossible match)
7.  PromQL only: allow the tenant label to be an empty string (missing) for specially configured metrics
8.  New label config CM format (in addition to the old one)
9.  Extended test cases
10. Rephrase and reformat some error messages

As time has passed, a notable percentage of the total code has been replaced.

## Relevance now that Grafana supports LBAC

Grafana itself now [supports label-based access control](https://grafana.com/docs/grafana/latest/administration/data-source-management/teamlbac/), however gaining access to the functionality appears to be expensive if you operate at some scale.  Its not very difficult or expensive to run a proxy that may meet your LBAC needs.