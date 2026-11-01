# Cloud module: provider documentation relied on (RTM S27/S28/S29, CM-142)

Retrieved 2026-11-01 from the official provider repositories or documentation sites. These are the only semantics the rules
assume; where a source is silent the rule returns **UNKNOWN**, never a pass. Attribute names are still not validated against
pinned provider schemas (CM-142): that needs the providers' released schema JSON and is tracked as open.

## Vultr: `vultr_firewall_rule`
Source: https://docs.vultr.com/reference/terraform/resources/firewall_rule
* Arguments: `firewall_group_id`, `protocol` (icmp, tcp, udp, gre, esp, ah), `ip_type` (v4, v6), `subnet`, `subnet_size`, optional `port`
  (TCP/UDP only; single port or colon-separated range), `notes`, `source` (`""` or `cloudflare`).
* There is no action or direction argument, so a rule is treated as an inbound allow rule.
* Not documented, so UNKNOWN: the meaning of an omitted `port` on a tcp/udp rule; the default behaviour of a firewall group.
* `source = "cloudflare"` means Cloudflare's ranges; exposure is not decided (UNKNOWN).

## IBM Cloud: `ibm_is_security_group_rule`
Source: https://github.com/IBM-Cloud/terraform-provider-ibm/blob/master/website/docs/r/is_security_group_rule.html.markdown
* `direction` (documented as `inbound` or `outbound`; the page's own example uses `egress`, so `inbound`/`ingress` and
  `outbound`/`egress` are accepted and any other value is UNKNOWN).
* `remote`: a security group ID, an IP address or a CIDR block. Omitted `remote` is not documented (UNKNOWN); a security-group ID
  cannot be judged as an address range (UNKNOWN).
* `protocol` omitted means `icmp_tcp_udp` (all protocols); `port_min`/`port_max` are required for tcp and udp. The nested
  `tcp`/`udp`/`icmp` blocks are deprecated and still read.

## UpCloud: `upcloud_firewall_rules`
Source: https://github.com/UpCloudLtd/terraform-provider-upcloud/blob/main/docs/resources/firewall_rules.md
* `firewall_rule` blocks with `action` (accept, drop), `direction` (in, out), `protocol` (empty, tcp, udp, icmp), `family`,
  source/destination address and port ranges expressed as start and end; both ends are required.
* Rules are evaluated in order and a default rule (only `action` and `direction`) "should be defined last".
* The behaviour when no rule matches is NOT documented: without a trailing catch-all drop the result is UNKNOWN. Address ranges are
  converted to CIDRs (at most 32 networks, otherwise UNKNOWN).

## cloud-init
Source: https://docs.cloud-init.io/en/latest/reference/modules.html (Set Passwords, Users and Groups, Runcmd, Write Files)
* `ssh_pwauth`: true/false; default is "leave unchanged", so an absent value is UNKNOWN.
* `plain_text_passwd`: documented as "an immediate security concern". `chpasswd.users[].type` defaults to `hash`; `text` is clear text.
  The deprecated `chpasswd.list` and the top-level `password` are treated as clear-text passwords.
* `sudo` rules are not syntax-checked by cloud-init; a rule containing `NOPASSWD` is reported.
* `runcmd` strings are interpreted by `sh`; a download piped to a shell (`curl|wget ... | sh`) is reported.
* `write_files` default permissions are 0644 (world-readable); file contents are never kept by the parser.
* Password values are replaced by a marker before anything is stored or reported.

## Researched but NOT implemented
* **VMware NSX-T (`nsxt_policy_security_policy`)**: the Terraform Registry reference could not be retrieved (the pages render client-side) and
  third-party pages disagree on value spellings. Not implemented; no claim is made.
* **Nutanix Flow (`nutanix_network_security_rule`)**: only a third-party (Pulumi) page was found, for the older resource; the Terraform
  argument reference was not retrieved. Not implemented; no claim is made.
* **IBM / Vultr / UpCloud pinned schemas**: attribute names come from the pages above, not from released provider schemas.
