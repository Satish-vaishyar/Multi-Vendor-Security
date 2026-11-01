# India provider discovery study (RTM S30, catalog section 2.4)

Status: **framework only, nothing here is a claim about any provider.** Every candidate below is "unverified" until a row in
the evidence table is filled in with a primary source (the provider's own public documentation) and the date it was read.
The module supports a provider only after it passes the per-provider definition of done (catalog section 10); until then the
capability matrix shows it as not supported, and this document does not change that.

## Why this is not pre-filled
Provider names, product names, IaC support and API availability change, and a wrong entry here would be shipped to customers as a
support statement. The study is therefore a checklist to be completed with evidence, not a list of conclusions.

## Candidates to assess (names only, no assertions about their capabilities)
Providers operating cloud or hosting services in India that customers have asked about or that appear in tenders. The list is
owned by Product and is expected to be edited; add a candidate only with the request that prompted it.

| Candidate | Requested by / source | Evidence collected | Verdict |
|---|---|---|---|
| (to be added) | | | unverified |

## Questions each candidate must answer (all with a link and a retrieval date)
1. Is there a public, documented infrastructure-as-code path (a Terraform provider, an OpenStack-compatible API, a CloudFormation-like
   template format, or Kubernetes only)? Name the exact provider/registry entry and its version.
2. Which resource types would carry security-relevant settings: network rules, object storage access, database exposure, encryption,
   identity, logging? List the documented attribute names for each.
3. Is there a published JSON/OpenAPI schema we can pin for fixtures (catalog section 10: pinned schemas)?
4. Is a read-only API role possible for live assessment, and which documented operations does it need (S31 read-only guard)?
5. Is the provider already covered by an adapter in this module because it exposes a standard interface (for example Kubernetes or
   OpenStack)? If yes, which fixtures prove it?
6. Licensing/terms: may we ship schemas or sample files derived from the documentation?

## Decision rule
* All of 1-3 answered with sources and fixtures written: add to the adapter backlog with an estimate (RTM S27-S29 template).
* Only Kubernetes or OpenStack applies: no new adapter, add fixtures and a note to the capability matrix.
* Anything unanswered: stays "unverified"; it is never listed as supported.

## Output of the study
A dated table in this file (candidate, sources, verdict) and, per accepted candidate, a new RTM step. No provider is mentioned in
product text, the README or the UI until its row says `verified` with sources.
