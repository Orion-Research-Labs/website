# Hunting Nation-State Spyware Infrastructure with Censys — Part 1: The Platform as a Threat Intelligence Primitive

*This is the first post in a series examining the infrastructure of commercial spyware vendors through the lens of internet-wide scanning data. Before we can hunt, we need to understand our primary instrument. This post is about Censys.*

---

## Why Internet Scanning Data Matters for Threat Intelligence

Commercial spyware vendors are, above all else, infrastructure operators. Whether it is Pegasus injection servers masquerading as mundane cloud tenants, Predator delivery nodes cycling through throwaway VPS providers, or Graphite command-and-control endpoints presenting carefully crafted TLS certificates, these actors leave physical traces on the public internet. They cannot avoid it. The moment a server is provisioned to deliver an exploit or receive stolen data, it acquires an IP address, opens ports, negotiates TLS handshakes, and begins generating the kinds of signals that internet-wide scanners are built to capture.

The challenge for threat intelligence practitioners is not whether those signals exist — it is whether you have a platform capable of capturing, indexing, and querying them at the speed and depth necessary for meaningful analysis. That platform, for the purposes of this series, is Censys.

This post is a technical orientation to the Censys Platform as it stands in late 2025: its scanning architecture, data model, historical data capabilities, the Threat Hunting Module, and the query language that makes all of it operationally useful. We also examine Censys Attack Surface Management (ASM) — a capability that, while primarily defensive in orientation, shares the same underlying internet map and is directly relevant to understanding how spyware operators construct their internet-facing footprints and how defenders can monitor for them continuously. If you are already deeply familiar with Censys, treat this as the methodological baseline against which the subsequent vendor analyses are built. If you are newer to internet scanning data as a threat intelligence primitive, this post should give you sufficient foundation to follow — and reproduce — everything that comes next.

---

## What Censys Actually Scans

Understanding Censys as a tool requires first understanding it as an infrastructure. Censys maintains a continuous, multi-pronged scanning operation across the entire public IPv4 address space, covering all 65,535 ports, and extending into IPv6 via DNS and redirect resolution. This is not periodic batch scanning — it is an ongoing process with scan freshness measured in hours, not days.

The scanning architecture has three primary components that matter for threat intelligence work.

**Global port scanning** covers the full IPv4 space across more than 100 IANA-assigned service ports using automatic protocol detection. This is the broadband layer — broad coverage, reliable detection of common services, the baseline from which everything else is seeded.

**Cloud provider acceleration** maintains a dedicated scanning docket for AWS, Azure, and GCP IP ranges, covering approximately one thousand ports per IP and targeting each at least daily. This is operationally significant because a substantial proportion of commercial spyware infrastructure is hosted on major cloud providers — either because operators deliberately use them for legitimacy camouflage, or because they rely on cloud-native VPS services. When a new C2 node spins up on a major provider, Censys has a high probability of observing it within 24 hours.

**Predictive scanning** is the most technically interesting component. Using historical service data as a training signal, Censys's predictive engine generates dynamic scanning targets — non-obvious IP/port combinations that behavioral patterns suggest are likely to yield active services. This currently accounts for over 40% of all service discoveries. For threat hunters, this means Censys is not simply documenting what is obvious; it is actively modeling where services are likely to exist based on historical activity. This is particularly relevant to spyware infrastructure, which tends to cluster on non-standard ports precisely to evade tools that only scan the well-known port space.

The average age of high-value service data in the Censys dataset is approximately 16 hours. For infrastructure that cycles rapidly — as commercial spyware operators are known to do — this scan frequency is meaningful. You will miss things. But you will miss far fewer things than you would with a platform that scans weekly or monthly.

One architectural detail with direct methodological implications: **Censys scans IP addresses, not hostnames.** Querying by hostname in the Platform searches against DNS enrichment data associated with host records — it does not perform hostname-initiated scanning. When a domain resolves to multiple IPs, or when a server is reachable only via direct IP access without a forward DNS record, the relationship between hostname intelligence from sources like SecurityTrails or VirusTotal and Censys host records must be established explicitly through IP-level pivoting. This is a recurring methodological constraint throughout this series, and the reason that multi-source approaches — combining SecurityTrails for historical DNS resolution, VirusTotal for passive DNS and malware correlation, and Censys for host-level service fingerprinting — consistently outperform single-platform queries.

---

## The Data Model: Hosts, Web Properties, and Certificates

Censys organizes its scan data into three top-level record types. Understanding their structure and relationships is prerequisite to writing effective queries.

### Hosts

A host record corresponds to a single IP address and is a hierarchically structured JSON object:

```json
{
  "ip": "<ipv4 or ipv6 address>",
  "service_count": "<integer>",
  "dns": {
    "names": [],
    "forward_dns": [],
    "reverse_dns": []
  },
  "location": {
    // continent, country, city, postal_code, timezone, coordinates
  },
  "routing": {
    // ASN, BGP prefix, BGP name, country
  },
  "services": [
    {
      "port": "<port number>",
      "protocol": "<protocol>",
      "transport_protocol": "<TCP|UDP|QUIC>",
      "software": [],
      "vulns": [],
      "threats": [],
      "banner": "",
      "banner_hash_sha256": "",
      "<service-specific details>": {}
    }
  ],
  "whois": {
    // name, CIDRs, organization, contacts
  }
}
```

Each element of the `services` array is a nested object describing a single observed service. This nesting structure is critical for query construction. Note the `threats` field within each service object: when you have access to the Threat Hunting Module, this field is enriched with mapped malware families, threat actor attributions, and tactical classifications for any service that matches known threat fingerprints.

As of late 2025, Censys also captures **web screenshots** for Enterprise users. Screenshots of ICS and remote desktop services are taken on every regular scan pass; HTTP/HTTPS screenshots are captured via Live Rescan and Live Discovery. For spyware infrastructure analysis, this provides a visual fingerprint layer — you can see what an operator's panel or delivery portal looks like, not just what its headers report.

### Web Properties

Web property records are indexed against hostnames and capture HTTP-layer behavior: response headers, HTML content, title strings, cookies, redirects, and favicons. For hunting spyware delivery infrastructure, web property records are often more discriminating than host records because they capture application-layer fingerprints that survive IP rotation. A Pegasus installation server that changes IPs but preserves its HTTP response headers — its `Server` string, its HTML title, its cookie naming convention — remains identifiable through web property queries even when its underlying IP has changed.

One recent change worth flagging: **Censys has migrated favicon hashes from MD5 to SHA-256**, accessible via `web.endpoints.http.favicons.hash_sha256`. Favicon hashing is a powerful infrastructure clustering technique — operators who reuse a web panel or delivery interface across multiple servers will present the same favicon, making the hash a durable pivot point. Any legacy queries using the old MD5 field (`favicons.md5_hash`) need to be updated for the current Platform.

### Certificates

Certificate records index every TLS certificate observed by Censys during scanning, including full parsed certificate data, trust chain validation across major root stores (Mozilla, Chrome, Apple), Certificate Transparency log entries, and revocation status.

For infrastructure hunting, certificates are one of the most powerful pivoting mechanisms available. The relationship between record types is bidirectional and exploitable: a host record presenting a TLS certificate contains the certificate's SHA-256 fingerprint in its service data. You can pivot from that fingerprint to the full certificate record, then from the certificate record to every other host currently presenting it, then from those hosts to their ASN registrations, then from ASN to organizational owner. This chain of pivots — from a single anomalous certificate to a cluster of co-registered infrastructure — is the structural basis of most of the analysis in this series.

---

## Historical Data: The Temporal Dimension of Infrastructure Analysis

Current-state data tells you what infrastructure looks like today. Historical data tells you what it looked like months ago, who was running what on which IP before a campaign went active, and whether an apparently new server was actually a reactivated asset from a previous operation. For spyware infrastructure analysis, this temporal dimension is often the difference between attributing a cluster and merely observing it.

Censys captures a snapshot of every IP it scans at the time of each scan. With sufficient access tier, you can reconstruct the historical configuration of a host — what services were running, what certificates were being presented, what banners were visible — at any past point covered by Censys's scan history. The depth of historical access scales with platform tier, from rolling months of host history on Core plans to extended historical ranges for Enterprise users with the Threat Hunting module.

For the vendor analyses in this series, historical data serves several specific analytical functions.

**Infrastructure timeline reconstruction** lets us establish when specific operator servers first appeared in Censys data, when they went dark, and whether they share registration or certificate patterns with earlier campaigns. When Citizen Lab or Google TAG document a Pegasus or Predator cluster, the IOCs they publish represent a snapshot at a specific point in time. Historical data lets us extend that snapshot backward — examining what those servers looked like before they were identified and whether they transitioned to new configurations afterward.

**Certificate host history** is particularly powerful for this work. Certificates can act as strong indicators of compromise because threat actors often reuse them across multiple assets over time. The Platform's Certificate Timeline visualization maps the complete history of which hosts and web properties have presented a given certificate, enabling you to pivot from a single known-bad certificate fingerprint to the full cluster of infrastructure that used it — not just currently, but over its entire observed lifetime. The timeline is filterable by port and protocol, and is part of the Threat Hunting module. For spyware infrastructure, where certificate reuse across operator-controlled servers is a documented pattern, this is one of the most operationally reliable analytical tools in the Platform.

**Historical host context for log enrichment** addresses a distinct operational problem. When investigating a historic compromise — reviewing logs from a breach that occurred months ago — current-state Censys data about a suspicious IP may be misleading, because the IP has since been reassigned or reconfigured. Historical scan data lets you query what was actually running on a given IP at the time of the logged activity, providing the context necessary for accurate attribution and triage.

**BigQuery access for large-scale retrospective analysis** is available to advanced users and provides SQL-queryable access to daily Censys snapshots. This enables questions that are difficult to express in real-time CenQL — for example, tracking the global count of hosts matching a specific infrastructure fingerprint over a 12-month period, or identifying the precise date when a specific certificate pattern first appeared across the IPv4 space. Censys's own research team has used BigQuery-based historical analysis to investigate NTC Vulkan infrastructure, demonstrating the method's utility for exactly the kind of state-sponsored infrastructure research this series undertakes.

---

## The Threat Hunting Module

The Censys Threat Hunting Module reached general availability on June 10, 2025, as part of the newly launched Censys Platform. It consolidates several capabilities into a coherent analytical workflow specifically designed for the work this series represents, and its development was directly informed by practitioners — including Silas Cutler, Principal Security Researcher at Censys, who helped architect it after extensive consultation with working threat hunters.

The **Threats Dataset** maps malware families, threat actors, and tactics to services or endpoints running on exposed hosts and web properties. Fingerprints are built from known malware deployments, URL endpoints associated with specific malware operations, and custom scanners for documented C2 frameworks including Cobalt Strike. Threat actor attribution uses Malpedia as a backing data source, enabling vendor-agnostic naming — you can query by CrowdStrike, Mandiant, or Microsoft threat actor designations interchangeably. The dataset also includes extended context per threat: alternative names, associated actor groups, and reference links that connect each detection to its underlying research. In the host data model, this populates `host.services.threats`, which becomes queryable in CenQL:

```
host.services.threats.type = "C2_SERVER"
```

As of October 2025, some threat data fields — including threat names and types — are visible to all Enterprise plan users in the Platform UI and via API, even without the Threat Hunting module add-on. Full search and pivot capabilities across threat data still require the module.

**CensEye** is an automated pivoting tool that identifies web assets sharing specific key-value pairs with an asset you are currently investigating. In practice, this means you can take a known-malicious host — one documented in a TAG or Citizen Lab disclosure — and have CensEye surface all other hosts that share its distinguishing characteristics: certificate fingerprints, HTTP response hashes, JARM fingerprints, favicon hashes, or banner strings. CensEye's default pivot fields have been significantly expanded and now include TLS fingerprinting fields (JA4S, JA3S, JA4X, JARM), SSH and protocol-specific pivots, HTTP metadata fields including headers, favicons, and body hashes, and support for specialized protocols including SCADA, Kubernetes, and SNMP. For spyware infrastructure hunting, CensEye compresses what would otherwise be hours of manual query iteration into a semi-automated clustering process.

**Live Discovery and Live Rescan** allow on-demand scanning of specific ports on specific hosts, producing side-by-side comparisons with the most recent scheduled Censys scan. Red text in the diff marks values present in the older scan that have been removed or modified — operationally, this is how you detect when an operator changes their configuration in response to a public disclosure, or when a server transitions from a staging state to an active delivery configuration.

**The Investigation Manager** provides a node-based pivot tree UI for visualizing and documenting connections between assets. For the kind of multi-hop pivoting this series employs — certificate → host cluster → ASN → organizational registration → related domain registrations — the Investigation Manager provides a structured workspace that makes analytical chains auditable and shareable across a team.

**The Certificate History Timeline** is a visual interface displaying when a certificate was observed on each host and web property across its full Censys-observed lifetime. This is the primary tool for temporal certificate analysis and will be central to the certificate-based analysis in the vendor posts that follow.

**The Threat Hunting MCP Server**, released in September 2025, allows AI agents to access the Threat Hunting APIs programmatically via the Model Context Protocol. This opens up workflows where automated agents can assist with large-scale infrastructure pivoting, enrichment, and pattern detection at a speed that manual analysis cannot match.

---

## Attack Surface Management: The Defensive Mirror

Censys Attack Surface Management (ASM) is oriented toward defensive use cases — helping organizations discover, inventory, and monitor their own internet-facing assets to identify exposure before attackers can exploit it. At first glance this may seem orthogonal to offensive infrastructure hunting. In practice the two capabilities are closely related, and understanding ASM illuminates both how spyware operators construct their own internet-facing footprints and how defenders can monitor for new operator infrastructure continuously.

ASM is built on the same underlying internet map as the Platform's threat hunting capabilities. The distinction is in the framing: where threat hunting asks "what malicious infrastructure exists on the internet," ASM asks "what of *your* infrastructure is visible to the internet — and is any of it exposed in ways you didn't intend?"

The ASM engine uses a seed-and-attribution model. You provide known organizational anchors — domains, IP ranges, ASN registrations, company names — and the attribution engine expands outward from those seeds to discover the full internet-facing footprint: subsidiary domains, cloud assets in AWS, Azure, GCP, and other providers, forgotten servers, misconfigured services, shadow IT that was never formally registered with the security team. Cloud Connectors sync asset data as frequently as every four hours, with domain, CIDR, subsidiary, and registrant changes tracked continuously via Continuous Seed Discovery. Each discovered asset is assessed against over 400 risk fingerprints, scored by severity based on impact, exploitability, and likelihood. Research indicates Censys ASM discovers up to 65% more of an organization's external attack surface than competing solutions — and given that over 66% of internet services run on non-standard ports, solutions that only cover standard ports are structurally blind to the majority of the attack surface.

For our research purposes, ASM is relevant in two specific ways.

First, it models **the adversary's reconnaissance perspective on target infrastructure**. A spyware operator conducting pre-operation reconnaissance against a target organization would perform something functionally similar to what Censys ASM does: discovering the complete internet-facing footprint, identifying exposed services, locating misconfigured assets that could serve as entry points. Understanding ASM's discovery methodology is directly useful for understanding what an attacker sees before deciding where to deliver an exploit.

Second, and more directly applicable to this series, ASM provides a **methodological template for operator infrastructure analysis**. Commercial spyware vendors are themselves organizations with internet-facing footprints. They register domains, provision cloud infrastructure, operate update servers, and run internal tooling — all of which generates the same kind of observable internet presence that ASM is designed to map. When we analyze Intellexa or Variston infrastructure, we are in effect conducting ASM against an adversary: seeding from known indicators, expanding attribution through DNS and certificate relationships, identifying the full cluster of registered assets. The ASM attribution model formalizes what threat hunters have been doing informally for years.

The **Saved Query Automation** feature in ASM allows queries to trigger real-time alerts via webhooks whenever a new asset matching the query criteria appears in Censys data. Combined with **Collections** — introduced in the April 2025 Platform update, which track both additions to and removals from a query result set over time — this creates a persistent surveillance mechanism. A query targeting the certificate issuance patterns, HTTP response signatures, favicon hashes, or port/protocol combinations associated with a known operator's infrastructure can alert the moment a new server matching those patterns comes online. This is how you detect the next campaign before the first victim device is compromised.

---

## The Censys Query Language (CenQL)

CenQL is the query interface for the Censys Platform. It is expressive enough to support complex multi-condition queries with boolean logic, nested field matching, regex, transport-layer fingerprint matching, fuzzy domain functions, and relative time arithmetic, while remaining readable enough that queries can be documented and shared as analytical artifacts.

A practical note before we dive in: as of June 2025, the Platform includes a **Query Assistant** — a natural language interface that generates valid CenQL queries from plain-English descriptions. It is available to all Platform users in beta and is useful for drafting initial queries that you then refine. The Platform also includes a **Censys Assistant** for Starter and Enterprise users that can generate a concise, human-readable summary of any host asset directly in the UI — useful for rapid triage of unfamiliar infrastructure. And for terminal-first workflows, the **cencli** command-line tool now brings full Platform search, lookup, and aggregation capabilities to the command line.

### Field-Value Pairs and Operators

The fundamental unit of a CenQL query is a field-value pair. Fields follow a dot-notation path mirroring the record type's JSON schema. The top-level prefix (`host.`, `web.`, `cert.`) scopes the query to the correct record type.

CenQL supports five primary comparison operators:

| Operator | Semantics | Example |
|----------|-----------|---------|
| `:` | Contains / tokenized match | `host.dns.names: censys.com` |
| `=` | Exact match | `host.dns.names = censys.com` |
| `=~` | Regex match | `host.services.cert.parsed.issuer.organization =~ "^[a-z0-9]{8}$"` |
| `<`, `>`, `<=`, `>=` | Range comparison | `host.service_count <= 3` |
| `:*` | Field exists with any value | `host.ip: *` |

The distinction between `:` and `=` matters operationally. The contains operator uses tokenization, so `host.dns.names: censys.com` will match `community.censys.com` and `censys.com.ar`. The exact operator will match only `censys.com`. For hunting, this determines whether you cast a wide net for related infrastructure or isolate a specific indicator.

**TLSH body hashing** — available via `host.services.http.response.body_hashes` — is worth calling out here. TLSH is a fuzzy hash that measures similarity rather than exact equality, meaning two HTTP responses with minor differences will have similar TLSH values. For spyware infrastructure hunting, this matters: operator servers that are functionally identical but return slightly different response bodies (due to session tokens, timestamps, or minor configuration variation) will cluster in TLSH space in ways that SHA-256 matching would miss entirely.

**Favicon hashes** are now SHA-256 via `web.endpoints.http.favicons.hash_sha256`. Matching on a favicon hash is a durable pivot: operators who reuse the same web panel across server rotations will present the same favicon regardless of what certificate or IP address they are currently using.

### The `twist()` Function

CenQL includes a built-in `twist()` function for typosquatting and domain impersonation detection:

```
web.hostname: twist("targetdomain.com") and not web.hostname = "targetdomain.com"
```

This generates permutations of the input domain — character substitutions, transpositions, homoglyphs — and returns web properties matching those permutations. For spyware infrastructure analysis, this is useful for detecting operator domains that impersonate legitimate update services, news sites, or organizational resources — a documented delivery technique across multiple vendors in this series.

### Boolean Logic and Parentheses

AND, OR, and NOT operators combine field-value pairs with standard boolean semantics (case-insensitive). One behavioral subtlety with significant implications for query precision: by default, boolean combinations evaluate against **the record as a whole**, not against a specific service within the record.

```
host.services.port = 443 and host.services.software.product = "nginx"
```

This returns all hosts that have port 443 open *and* have nginx running anywhere on the host — not necessarily nginx specifically on port 443. For infrastructure hunting, this distinction is often the difference between a high-signal query and a noise-filled one.

### Nested Field Queries

To require that multiple conditions hold simultaneously within a single service object, use nested field syntax:

```
host.services: (port = 8443 and software.product = "nginx")
```

The parenthesized expression after `host.services:` is evaluated against each individual service object. This returns only hosts where a single observed service is both on port 8443 and identified as nginx — a meaningfully different and tighter result set.

For certificate-based hunting, nested field queries are indispensable:

```
host.services: (
  cert.parsed.issuer.organization =~ "^[a-z0-9]{8}$" and
  cert.parsed.issuer.locality =~ "^[a-z0-9]{8}$" and
  cert.parsed.issuer.common_name =~ "^[a-z0-9]{8}$"
)
```

This pattern — requiring multiple certificate fields to simultaneously match a random-string pattern on the same service — is a documented detection technique for specific malware families and forms the basis of similar queries we will apply to spyware infrastructure in subsequent posts.

### Regular Expressions

CenQL supports PCRE-compatible regex via the `=~` operator with backtick-delimited patterns. Regex is unanchored by default — use `^` and `$` anchors to enforce full-value matching. Special characters require double-escaping. Regex requires a Starter plan or above.

```
web.hostname =~ `^[a-z]{6,12}\.(cloud|io|net)$`
```

Regex is particularly valuable when you know the structural pattern of infrastructure identifiers — randomized subdomain lengths, specific TLD preferences, character class constraints — but cannot predict the specific values. Commercial spyware operators generating domain names programmatically often exhibit detectable patterns precisely because programmatic generation is constrained: predictable character sets, consistent length ranges, limited registrar diversity.

### Transport-Layer Fingerprints: JARM, JA3, JA4+, and More

Beyond structured fields, Censys captures cryptographic fingerprints of TLS negotiation behavior. JARM is an active TLS fingerprinting method that characterizes how a server responds to a crafted series of TLS ClientHello packets — different server configurations produce different JARM fingerprints, enabling identification of servers running the same underlying software stack even when they present different certificates or respond on different ports. JA3, JA4+, JA3S, JA4S, and JA4X extend this to passive fingerprinting derived from observed handshake parameters. All are exposed as queryable fields and as CensEye pivot dimensions:

```
host.services: (jarm.fingerprint = "<known-fingerprint>")
```

For spyware C2 infrastructure, JARM fingerprints have proven durable as indicators. Several major vendors have been documented reusing server configurations across campaigns in ways that produce consistent JARM signatures that persist even when IPs, domains, and certificates are rotated, because they reflect the underlying server software and TLS configuration rather than the credential material presented.

### Time Variables and Relative Time Queries

CenQL supports relative-time variables: `h` (hour), `d` (day), `w` (week), `M` (month), `y` (year), and `now`. Combine these with range operators to scope queries temporally:

```
cert.added_at > "now-24h"
```

```
host.services.cert.added_at > "now-1d/d" and host.services.cert.added_at < "now/d"
```

The `/d` suffix rounds to the nearest day boundary. For tracking newly provisioned infrastructure associated with an active campaign, real-time temporal queries are operationally critical. For retrospective analysis, they help scope when specific patterns first appeared in Censys data.

### Collections: Persistent Query Monitoring

Collections, introduced in April 2025, allow you to save a CenQL query and track its results persistently over time, monitoring both additions and removals. Webhook integration means alerts can feed directly into SIEM, SOAR, or custom notification pipelines.

For spyware infrastructure monitoring, Collections convert a one-time hunt into continuous surveillance. Once you have built a high-confidence query that characterizes a specific operator's infrastructure fingerprint — and the vendor analyses in this series will produce exactly those queries — Collections let that query run continuously, alerting you whenever new infrastructure matching that fingerprint comes online.

### Value Ranges with Bracket Syntax

Multiple explicit values can be grouped using `{}` bracket syntax:

```
host.location.country: {"Germany", "Netherlands", "Luxembourg"}
```

```
host.services.port: {443, 8443, 4443}
```

Useful for hunting across known hosting regions or port sets associated with a specific operator's infrastructure profile.

---

## What This Enables: Infrastructure Attribution at Scale

The combination of Censys's scanning depth, historical data, the Threat Hunting Module, ASM attribution methodology, and CenQL's full query expressiveness creates a specific analytical capability: the ability to identify clusters of infrastructure that share observable technical properties, independently of whether those properties are documented IOCs.

This is the distinction between *indicator matching* and *infrastructure hunting*. Indicator matching takes known-bad values — IP addresses, domains, certificate fingerprints — and checks whether they appear in your dataset. It is reactive and dependent on prior disclosure. Infrastructure hunting takes observable technical patterns — certificate issuance profiles, HTTP response signatures, JARM fingerprints, TLSH-similar response bodies, favicon hashes, ASN clustering, port/protocol combinations — and queries for hosts that match those patterns regardless of whether they have been previously identified as malicious.

The practical payoff is that you can find infrastructure *before* it is used. A freshly provisioned server that has not yet delivered a single exploit will still present a TLS certificate, respond to HTTP probes, and register a banner — all of which may match the fingerprint of previously documented operator infrastructure. This is how Citizen Lab and Google TAG have repeatedly identified Pegasus, Predator, and Graphite infrastructure: not by waiting for victim devices to report C2 addresses, but by recognizing that operator infrastructure has consistent, detectable technical signatures that persist across IP rotation, domain changes, and provider migrations. Censys has a documented history of directly assisting Citizen Lab in exactly this kind of mercenary spyware infrastructure analysis.

The posts that follow apply this methodology systematically to each vendor. Each will include the original canonical disclosure sources, the specific technical signatures documented by Google TAG, Citizen Lab, Meta Security Research, and others, and the CenQL queries — constructed and validated against live Censys data — that operationalize those signatures for active hunting.

The infrastructure is out there. We know what to look for. Let's start looking.

---

*If you have corrections, additions, or relevant technical disclosures I should incorporate, reach out. This work is better when it is collaborative.*
