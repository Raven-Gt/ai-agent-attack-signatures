# Deployment guide

How to load the signature set into each platform, how to validate it before production, and
how to tune the behavioural detector.

---

## 0. Before you deploy anything

Three checks, in this order. Do not skip the first one.

### 0.1 Replay your own traffic

The T1 set matched **zero** rules across 9,905,794 public internet requests and 142,705 real
WAF attack transactions. Your environment is different, so confirm it:

```bash
# Elasticsearch / OpenSearch - replay a week of traffic
# (rule file: signatures/ioc_rules_es.kql)
for q in $(grep -v '^#' signatures/ioc_rules_es.kql); do
  echo "$q" | curl -s -XPOST 'http://localhost:9200/_search' \
    -H 'Content-Type: application/json' \
    -d '{"query":{"bool":{"must":[{"query_string":{"query":"$q"}}],"filter":[{"range":{"@timestamp":{"gte":"now-7d"}}}]}}}' \
    -o /dev/null -w "%{http_code} $q\n"
done
```

A run of `200` with a non-empty `hits.total` means the rule matched something in your traffic.
Investigate it before deploying. Expect **0** for well-scoped rules; a handful of hits on
broad ones is a signal that the rule needs narrowing, not that the corpus was wrong.

### 0.2 Exclude the scanners you already know about

Measured false-positive rate differs sharply by population: **2.72%** on browser-driven real
attackers, **66.67%** on enumeration-tool actors. If you run scanners from a known source
range, exclude that range before evaluating.

### 0.3 Decide the alert unit

The signature set answers *which framework*. It does not answer *was this an AI agent* - see
`docs/LIMITATIONS.md`. Plan the alert on the **actor** (one source address within a time
window), never on the individual request.

---

## 1. Elasticsearch / OpenSearch

### 1.1 Load

```bash
# each non-comment line is a standalone KQL query; load them as saved objects
grep -v '^#' signatures/ioc_rules_es.kql | while IFS= read -r q; do
  id=$(echo "$q" | md5sum | cut -c1-16)
  curl -s -XPOST "http://localhost:9200/_search/saved_object/_doc/$id?overwrite=true" \
    -H 'Content-Type: application/json' \
    -d "{\"attributes\":{\"title\":\"AI agent signature $id\",\"query\":{\"query\":\"$q\"}},\"core\":{}}"
done
```

Or, if you use the Elastic detection rules format, convert with the official tooling:
```
https://github.com/elastic/detection-rules
```

### 1.2 One-shot detection query (no saved objects needed)

```
GET access-*
@timestamp: [now-7d TO now] AND (
  user_agent : /@mixedbread\-ai\/unstructured/
  OR http.request.headers.x_request_id : /^[0-9a-f]{12}$/
  OR user_agent : /RAPTOR\ Security\ Scanner\ \(Authorized\ Testing\)/
  OR user_agent : /HexStrike\-HTTP\-Framework\/[0-9]+\.[0-9]+\ \(Advanced\ Security\ Testing\)/
  OR url.original : /\/doesnotexist_[^ \t\/]+/
)
```

### 1.3 Combinatorial criterion

Do not alert on a single signature. On 9.9M requests, 31 source addresses matched one rule
and **exactly one** matched two. Alert on >= 2 distinct rule IDs within one actor window:

```
GET access-*
@timestamp: [now-1h TO now]
| stats dc(rule_id) as rules by source.ip
| where rules >= 2
```

---

## 2. Splunk

```bash
grep -v '^#' signatures/ioc_rules_splunk.spl
```

Each line is a standalone SPL search. For deployment, wrap them in a saved search named
`ai_agent_signature` and add the actor aggregation:

```
index=access sourcetype=* 
  [ | search ueseragent="*mixedbread-ai/unstructured*" OR ueseragent="*RAPTOR Security Scanner*"
    | eval rule_id="ioc-001" ]
  [ | search url="*doesnotexist_*" 
    | eval rule_id="ioc-002" ]
| stats dc(rule_id) as rules by src
| where rules >= 2
```

---

## 3. Suricata / Snort

```bash
cp signatures/ioc_rules_suricata.rules /etc/suricata/rules/
suricata -T -c /etc/suricata/etc/suricata.yaml    # test the ruleset
systemctl reload suricata
```

The file uses `http.user_agent`, `http.header`, `http.uri` and `http.request_body` buffers.
Body rules require `body` inspection to be enabled in `suricata.yaml`; without it the body
class rules silently never fire. Check with:

```bash
suricata -T -c /etc/suricata/etc/suricata.yaml 2>&1 | grep -i 'rule.*error'
```

---

## 4. Sigma (web proxy)

```bash
sigma check -t splunk signatures/ioc_rules_sigma.yml
sigma convert -t splunk signatures/ioc_rules_sigma.yml
```

The Sigma file carries the User-Agent rules only; the HTTP header and path rules have no
Sigma webproxy equivalent and must be deployed to the proxy or WAF directly.

---

## 5. The behavioural detector

### 5.1 Run it

```bash
cd research
pip install -r requirements.txt
python pipeline/score_actor.py --input ../data/positive --out ../out/actor
python evaluation/false_positive_eval.py --features ../data/features --out ../out/fp.json
```

### 5.2 Threshold selection

| Threshold | Segment recall | Framework recall | FPR on real attackers | FPR on scanner actors |
|---|---:|---:|---:|---:|
| 0.27 | 15/15 | 12/12 | 2.72% | 66.67% |
| **0.35 (default)** | **13/15** | **10/12** | **2.72%** | **66.67%** |
| 0.50 | 11/15 | 8/12 | 0.19% | 66.67% |

The threshold does not help against tool-driven traffic at any value - see
`docs/LIMITATIONS.md`. If your environment is scanner-heavy, the behavioural layer is not
the right control and you should rely on the signature layer plus egress correlation.

### 5.3 What to correlate with

An AI agent must call an LLM provider. That outbound traffic is attributable in a way
target-side traffic is not. The detection rule for it is described in
`docs/LIMITATIONS.md` section 1; it requires egress logs, which a passive HTTP sensor does
not have.

---

## 6. Maintenance

Signatures decay as upstream frameworks change their markers. Subscribe to releases, and if
you maintain one of the covered frameworks, see `CONTRIBUTING.md`.
