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
8.  New label config CM format (in addition to the old CM format and MySQL)
9.  Optional header which can be used to define group membership
10. Extended test cases
11. Rephrase and reformat some error messages

As time has passed, a notable percentage of the total code has been replaced.

## Relevance now that Grafana supports LBAC

Grafana itself now [supports label-based access control](https://grafana.com/docs/grafana/latest/administration/data-source-management/teamlbac/), however gaining access to the functionality appears to be expensive if you operate at some scale.  Its not very difficult or expensive to run a proxy that may meet your LBAC needs.

## Various Options to Configure Label Enforcement

This fork of [multena-proxy](https://github.com/gepaplexx/multena-proxy) adds new options.

User name and group membership is determined in one of two ways:
1.  An OAuth HTTP header that establishes user name and group membership, suitable for a proxy instance serving one Grafana that is being shared between teams
2.  A special HTTP header that lists group membership (typically protected by symmetric encryption), suitable for a proxy instance that is serving multiple Grafana instances, each of which is dedicated to a team

Users, groups or just connections can be flagged for LBAC bypass (sometimes called "admin" rights) by one of:
1.  a single group specified in the main configuration, *and/or*
2.  (for the old label config CM format) a special value specified in the main configuration, which is then included as a label value in the label configuration, serving as a flag for the associated user or group, *and/or*
3.  (for the new label config CM format) a dedicated section lists flagged users and groups, *and/or*
4.  a special HTTP header and value which renders user or group membership unimportant