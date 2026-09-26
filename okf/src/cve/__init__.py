"""CVE engine package: deterministic CPE → CVE → version-range correlation.

-half: NO ML for the verdict (cve_okf §21). LLM (via llm_gateway only) may
extract vendor/product/version pre-lookup; the affected decision is pure logic.
Modules map to cve_okf §20 (8 modules).
"""
