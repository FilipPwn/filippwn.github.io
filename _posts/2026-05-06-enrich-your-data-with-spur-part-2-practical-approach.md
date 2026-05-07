---
layout: post
title: "Enrich Your SIEM Data with Spur, Part 2 - Practical Approach"
date: 2026-05-06
tags: [detection, siem, enrichment, elastic, spur]
description: "How to practically enrich logs with Spur using an enrichment engine, Logstash and Elastic."
---

## Introduction

In [Part 1](/blog/2026/04/enrich-your-data-with-spur/) I wrote about the theory behind Spur enrichment: why VPN, proxy, Tor and residential proxy context matters, and which fields are useful for detection.

This post is the practical part. Instead of talking only about the data model, I'll show a practical SIEM enrichment flow.

The project is here: [Enrichment Engine](https://github.com/FilipPwn/Enrichment-Engine) - I've built it in my spare time.

The idea is simple: use enrichment engine as enrichment proxy between SIEM and Enrichment provider (like Spur). It will be used to enrich IP's and enable hunting using it's data in SIEM.

![Enrichment Engine architecture](/assets/images/spur/enrichment-engine-architecture.svg)

## The Enrichment Engine

I created a small Docker Compose project for this exact use case. It has three components:

- **Nginx** — reverse proxy and short-term cache for repeated requests
- **FastAPI app** — validates IPs, talks to providers and returns JSON
- **Postgres** — long-term cache for provider responses

A request walks through the stack in order. Nginx serves a short-term cached response if it has one. On a miss the request reaches FastAPI, which validates the IP — invalid addresses are rejected here — and then checks Postgres for a longer-lived entry. Only when nothing useful is cached does FastAPI actually call Spur, write the result to Postgres with a TTL, and return it. The same IP therefore costs at most one upstream call per cache window, no matter how many Logstash workers ask for it.

Spur is the first provider, but the project is written so other providers can be added later, for example AbuseIPDB or VirusTotal.

The shape of a request is just `GET /enrich/{ip}?providers=spur`. For a VPN exit node, the engine returns the Spur payload with a `stale` flag attached by the engine itself:

```json
{
  "ip": "194.233.96.206",
  "infrastructure": "DATACENTER",
  "organization": "Packethub S.A.",
  "location": {
    "city": "Berlin",
    "country": "DE",
    "state": "State of Berlin"
  },
  "tunnels": [
    {
      "anonymous": true,
      "operator": "NORD_VPN",
      "type": "VPN"
    }
  ],
  "risks": ["TUNNEL"],
  "stale": false
}
```

A few details about the engine matter for what comes next:

- `stale` is added by the engine, not Spur — it cahnges to `true` when the upstream call fails and the cache serves a previously stored response. Useful as a flag in detection logic when enrichment may be old.
- Invalid, private, loopback and link-local IPs are rejected at the edge.
- `X-App-Cache` (`HIT` / `MISS` / `BYPASS`) is exposed as a response header, so cache effectiveness is visible without leaving HTTP.

The point isn't this specific implementation. It's that one internal service should own validation, caching, retries, budget visibility and provider abstraction — not every Logstash worker.

## Where to enrich

The most useful place to start enriching is identity telemetry from the internet — anywhere the IP is tied to a user and has a `result` you actually care about. In practice that means VPN appliance logons, Entra ID / Okta / Duo and other SSO, ADFS, OWA, RDP Gateway, Citrix, and authentication on internet-facing applications.

What I would *not* enrich on day one any flows without clear user context. The IP is there, but the identity decision is not — so the enrichment cost rarely pays off.

## Logstash filter approach

If your logs pass through Logstash, the natural place to enrich is at ingest time with the HTTP filter. Conceptually:

```ruby
filter {
  if [source][ip] and [event][category] == "authentication" {
    http {
      url => "http://enrichment-engine:8080/enrich/%{[source][ip]}?providers=spur"
      verb => "GET"
      target_body => "[enrichment][spur]"
      headers => { "Accept" => "application/json" }
      connect_timeout => 2
      request_timeout => 5
      automatic_retries => 1
    }
  }
}
```

## Cache strategy and API limits

This is the part that can hurt you if you ignore it.

Let's say your Spur plan allows **1,000,000 lookups per month**. That sounds generous, but the cost isn't driven by event volume — it's driven by how many *unique public IPs* you enrich within the cache window. TTL choice converts directly into upstream call volume:

![Cache strategy](/assets/images/spur/cache-strategy.svg)

Before enabling enrichment for a noisy source, measure it in Elastic. Assuming GeoIP enrichment tags private addresses (so `source.as.organization.name` is `"private"` for RFC1918 / loopback / link-local), the count is a single ES|QL query:

```esql
FROM logs-*
| WHERE @timestamp >= NOW() - 30 days
| WHERE event.category == "authentication"
| WHERE source.ip IS NOT NULL and source.as.organization.name != "private"
| STATS unique_public_source_ips = COUNT_DISTINCT(source.ip)
```

Two habits keep the budget stable once the TTL is sized: treat Nginx as a short burst absorber rather than your primary cache, and reserve `fresh=true` for manual investigations rather than normal ingest. Aim for 20-30% monthly lookup headroom so incident bursts and backfills do not push you over.

## How I would operationalize it

The deployment path I would follow is small on purpose:

1. Pick one high-value identity source — Entra ID sign-ins, VPN logons, the SSO that fronts your most sensitive apps.
2. Measure unique public IPs for the last 30 days against your monthly Spur limit.
3. Choose a TTL that keeps projected lookups well below that limit, with headroom for incidents.
4. Add Logstash enrichment for that one source only.
5. Store the response under `enrichment.spur` and leave ECS fields alone.
6. Hunt first; promote to detections only when the noise profile is understood.

A few patterns are worth pursuing once enrichment is in place:

- successful logon from `VPN`, `PROXY` or `TOR` for a privileged account
- password spraying tied to a single VPN or proxy operator
- first successful logon for a user from a given `tunnels.operator`
- impossible travel paired with `enrichment.spur.risks: TUNNEL`
- residential proxy activity surfacing in `enrichment.spur.client.proxies`

The simplest hunt to start with is just surfacing every event Spur attached a risk tag to:

```esql
FROM logs-*
| WHERE enrichment.spur.risks IS NOT NULL
| SORT @timestamp DESC
```

![Sample log](/assets/images/spur/sample_log.png)

The thing to avoid is treating `tunnels.type: VPN` as a verdict. Plenty of legitimate users authenticate through commercial VPNs, especially mobile users. The signal you want is the combination of anonymized infrastructure with a behavior that does not fit the user — a new operator, a new country, a spike in failures, a successful logon at the tail of a spray. Enrichment is context, not a decision.

## Summary

Spur enrichment earns its keep when it is attached to logs where identity decisions happen — internet-facing logons first. Put an internal service between your SIEM pipeline and the provider, cache aggressively, and enrich only the events where the context will actually be used in detection.

The key lesson: don't enrich everything. Measure unique public IP volume, pick a TTL that respects your monthly limit, and start small. The [Enrichment Engine](https://github.com/FilipPwn/Enrichment-Engine) is a starting point — a small API with validation, caching and provider abstraction that Logstash can attach to identity events.
