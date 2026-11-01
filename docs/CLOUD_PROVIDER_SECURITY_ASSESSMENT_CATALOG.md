# Cloud Provider Security & Compliance Assessment

## Provider catalogue, upload formats, and sample configuration fixtures

**Audience:** Cloud-security implementation engineer / OpenCode coding agent  
**Purpose:** Build the cloud-assessment module for a multi-cloud security platform. A customer uploads infrastructure configuration files; the platform identifies the cloud provider and IaC format, parses resources and relationships, then runs security-misconfiguration and evidence-backed compliance checks.

**Document status:** Engineering requirements and sample fixtures. Provider APIs, resource schemas, API versions, and benchmark versions change. Validate every fixture against the current provider schema and pin tool/provider versions in CI before treating it as a conformance test.

---

## 1. Product requirement and critical boundary

The cloud module must support two distinct assessment modes:

1. **Upload-only / static IaC assessment:** Assess what the uploaded files declare. Detect insecure resource properties, overly permissive network rules, weak encryption settings, public storage, risky IAM grants, missing logging, exposed management ports, insecure Kubernetes settings, and configuration relationships visible in the uploaded source.
2. **Connected / live-cloud assessment:** With explicit customer authorization and read-only credentials, query cloud APIs to assess the deployed environment, effective IAM, inherited organization policies, actual public exposure, enabled logging, key status, resource drift, and controls that cannot be proven from IaC alone.

Never report an upload-only assessment as proof that the deployed account is secure or compliant. A Terraform plan/configuration is desired state, not evidence of the live state. A Terraform state file may contain secrets and should not be required for the normal upload flow.

### 1.1 Assessment result labels

Every control finding must carry one of these evidence states:

- `PASS_STATIC`: configuration explicitly demonstrates the control is met.
- `FAIL_STATIC`: configuration explicitly demonstrates a violation.
- `UNKNOWN_STATIC`: required property is omitted, computed, inherited, dynamically generated, or unavailable in the uploaded files.
- `NOT_APPLICABLE`: control does not apply to the detected resource/service.
- `PASS_LIVE` / `FAIL_LIVE` / `UNKNOWN_LIVE`: result comes from a live API assessment.
- `CONFLICT`: uploaded configuration and live API state disagree.

Do not silently convert `UNKNOWN` into `PASS`. Make evidence source, resource address/ID, file path, line/column, parser version, rule version, and assessment timestamp visible in the result.

---

## 2. Cloud providers and platform scope

There is no finite list of literally every cloud provider: regional hosts, managed service providers, sovereign clouds, private clouds, and new platforms appear continually. Build provider support through adapters and a capability registry, rather than hard-coding the entire product around a fixed list.

### 2.1 Priority 1 — major public-cloud providers

| Provider | Common IaC/configuration sources to accept | Recommended initial assessment scope | Benchmark availability |
|---|---|---|---|
| Amazon Web Services (AWS) | Terraform/OpenTofu HCL and JSON; Terraform plan JSON; CloudFormation YAML/JSON; AWS CDK synthesized CloudFormation; SAM templates; selected AWS Config exports | IAM, VPC, security groups, NACLs, S3, KMS, CloudTrail, Config, EC2/EBS, RDS, load balancers, EKS, secrets | CIS AWS Foundations and service-specific CIS benchmarks |
| Microsoft Azure | Terraform/OpenTofu; ARM JSON; Bicep; Terraform plan JSON; Azure Policy definitions/assignments; selected export/template artifacts | Entra/Azure RBAC, subscriptions, management groups, VNets/NSGs, Storage, Key Vault, SQL, VMs/disks, AKS, Defender, Monitor/Activity Logs | CIS Microsoft Azure Foundations and service-specific benchmarks |
| Google Cloud Platform (GCP) | Terraform/OpenTofu; Terraform plan JSON; Google Cloud Infrastructure Manager Terraform configurations; selected Config Controller/KRM YAML; organization policy YAML/JSON exports | IAM, organization/folder/project policies, VPC/firewall, Cloud Storage, Cloud KMS, audit logs, Compute Engine, Cloud SQL, GKE, load balancing | CIS Google Cloud Platform Foundation |
| Oracle Cloud Infrastructure (OCI) | Terraform/OpenTofu HCL/JSON; OCI Resource Manager ZIP; supported OCI CLI/API JSON exports | IAM policies/groups, compartments, VCN/security lists/NSGs, Object Storage, Vault/KMS, Audit, Logging, Compute, DB systems, OKE | CIS OCI Foundations |
| Alibaba Cloud (Aliyun) | Terraform/OpenTofu; Resource Orchestration Service (ROS) JSON/YAML; supported ROS Terraform packages; selected resource exports | RAM, VPC/security groups, ECS, OSS, KMS, ActionTrail, RDS, ACK, SLB | CIS Alibaba Cloud benchmark |
| IBM Cloud | Terraform/OpenTofu; IBM Cloud Schematics workspaces/configuration archives; selected Security and Compliance Center profiles/results | IAM, accounts, VPC, security groups, COS, Key Protect, Activity Tracker, Kubernetes Service, Databases | CIS IBM Cloud Foundations |
| Tencent Cloud | Terraform/OpenTofu; Tencent Cloud Infrastructure-as-Code / CloudFormation-compatible templates where applicable; supported API exports | CAM, VPC/security groups, CVM, COS, KMS, Cloud Audit, TKE, TencentDB, CLB | Use CIS/cloud-provider mappings where available; do not claim a CIS Tencent benchmark unless a current official benchmark is verified |
| Huawei Cloud | Terraform/OpenTofu; Cloud Stack/CloudFormation-compatible templates where officially supported; supported API/Config exports | IAM agencies/permissions, VPC/security groups, ECS, OBS, KMS, CTS, RDS, CCE, ELB | Use provider and customer control baselines; do not claim a CIS Huawei Cloud benchmark unless verified |

### 2.2 Priority 2 — alternative / regional public-cloud providers

| Provider | IaC / config path | Notes for adapter |
|---|---|---|
| DigitalOcean | Terraform/OpenTofu (`digitalocean` provider), API export where available | Droplets, Cloud Firewalls, VPCs, Spaces, managed databases, load balancers, Kubernetes clusters |
| Akamai Connected Cloud (Linode) | Terraform/OpenTofu (`linode` provider), API export | Linodes, Cloud Firewalls, VLANs, NodeBalancers, Object Storage, LKE |
| Hetzner Cloud | Terraform/OpenTofu (`hcloud` provider), API export | Servers, Firewalls, networks, volumes, load balancers, primary IPs |
| Vultr | Terraform/OpenTofu (`vultr` provider), API export | Instances, firewall groups/rules, VPC, block storage, object storage, load balancers, Kubernetes |
| OVHcloud | Terraform/OpenTofu (`ovh` provider), API export | Public Cloud projects, private networks/subnets, instances, managed databases, load balancers, Object Storage |
| Scaleway | Terraform/OpenTofu (`scaleway` provider), API export | Instances, security groups, private networks, Object Storage, managed databases, Kapsule Kubernetes |
| UpCloud | Terraform/OpenTofu (`upcloud` provider), API export | Servers, firewall rules, networks, managed databases, object storage |
| Equinix Metal | Terraform/OpenTofu (`equinix` provider), API export | Bare-metal projects, VLANs, VRFs, gateways, device/network configuration; distinguish bare metal from a full hyperscaler control plane |

### 2.3 Priority 3 — private cloud, hosted cloud, and cloud-native platforms

| Platform | Configuration sources | Scope / caveat |
|---|---|---|
| OpenStack | Terraform `openstack` provider; Heat templates; cloud-config; selected Neutron/Nova/Keystone API exports | Keystone IAM, Neutron networks/security groups/routers, Nova, Cinder, Swift, Octavia. Vendor distributions may add extensions. |
| VMware vSphere / Cloud Foundation | Terraform `vsphere` provider, vRealize/Aria Automation blueprints, NSX Terraform provider/API exports | vSphere inventory/VM/networking and NSX segmentation; not a replacement for vCenter/NSX live assessment. |
| Nutanix Cloud Platform | Terraform provider, Calm blueprints, Prism API exports | Validate supported resource coverage against current provider/schema. |
| Kubernetes (any cloud/on-prem) | Kubernetes YAML/JSON manifests, Helm charts, Kustomize overlays, Kustomize output, supported policy resources | Separate cluster/workload benchmark from cloud-account benchmark. Include RBAC, Pod Security, network policies, secrets, admission, API server and workload controls. |
| Crossplane | Kubernetes YAML/JSON, Composition and XRD resources | Parse desired cloud resources but resolve provider-specific semantics. Compositions can hide actual resource properties. |
| Pulumi | Pulumi YAML and exported deployment/state formats where supported; language-based TypeScript/Python/Go/C#/Java projects | Static analysis of general-purpose code is harder. Prioritize exported deployment JSON or provider-specific resource graph; do not claim full analysis from source text alone. |
| AWS CDK / Azure CDK / CDK for Terraform | Synthesized CloudFormation/ARM/ Terraform output | Prefer scanning synthesized output and preserve source-to-synthesized provenance. |
| Ansible / cloud-init | YAML playbooks, roles, cloud-init user-data | These are provisioning/configuration inputs, not a complete representation of a cloud account. Scan for exposed secrets, unsafe commands, insecure OS settings, and cloud-init risks. |

### 2.4 India-focused provider discovery

Research and evaluate Indian cloud, colocation, hosting, and sovereign-cloud platforms such as E2E Networks, CtrlS, Yotta, Sify, ESDS, NxtGen, Tata Communications, RailTel/NIC ecosystem offerings, and other providers selected by customer demand. Treat these as **discovery candidates**, not as pre-verified Terraform providers or API integrations.

For each candidate, record:

- Legal product/provider name and product type (public cloud, managed hosting, colocation, sovereign cloud, GPU cloud, private cloud, etc.).
- Whether customers can export IaC, inventory, policy, network, IAM, and audit configuration.
- Official API documentation, CLI, SDK, Terraform provider, OpenStack compatibility, Kubernetes API, and versioning policy.
- Authentication model, available read-only roles, API rate limits, region coverage, and audit evidence.
- Whether the provider runs OpenStack, VMware, Kubernetes, or proprietary control-plane technology.
- Exact features tested, product/region/API version and evidence date.

If the provider exposes OpenStack-compatible APIs, use the OpenStack adapter for compatible resources, but retain an explicit provider identity and mark unsupported extensions as unknown. Do not label an OpenStack-compatible control plane as fully supported without tests against that provider.

---

## 3. File upload support matrix

### 3.1 Accept these files and archives

| Type | Extensions / names | Handling |
|---|---|---|
| Terraform / OpenTofu HCL | `.tf`, `.tfvars`, `.tfvars.json`, `.tf.json`, `.hcl` | Parse HCL; resolve local variables/modules where safely available; do not run `apply`. |
| Terraform plan | `.tfplan`, JSON from `terraform show -json` | Prefer plan JSON; distinguish planned values from known values and unknown/computed values. |
| Terraform state | `.tfstate`, state JSON | Sensitive: warn and require explicit opt-in; redact secret values; do not persist raw state by default. State is not required for static scanning. |
| AWS CloudFormation | `.yaml`, `.yml`, `.json`, `.template` | Parse template sections, intrinsic functions, transforms, nested stacks and macros; unresolved dynamic values become `UNKNOWN_STATIC`. |
| AWS SAM / CDK output | SAM YAML/JSON; synthesized CloudFormation | Normalize to CloudFormation resource model; retain source mapping if supplied. |
| Azure ARM | `.json` | Parse parameters, variables, resources, nested/linked templates and expressions. |
| Azure Bicep | `.bicep`, `.bicepparam` | Use a pinned Bicep compiler/parser in a sandbox to build ARM JSON; keep original source and compiled output. Never execute deployments. |
| Google Cloud IaC | Terraform HCL/JSON and plan JSON; supported KRM YAML/JSON; Infrastructure Manager configuration archives | Deployment Manager is legacy only: do not make it a new-platform default. Google Cloud Deployment Manager support ended April 1, 2026; guide customers to Infrastructure Manager or Terraform. |
| Alibaba ROS | `.yaml`, `.yml`, `.json`, Terraform configuration archive | Parse ROS resource types and intrinsic functions; ROS templates are JSON/YAML and ROS also supports Terraform workflows. |
| OCI Resource Manager | ZIP containing `.tf` and related config files; `.tf`, `.tf.json` | Inspect archive root and Terraform files; reject state files by default. |
| Kubernetes / Helm | `.yaml`, `.yml`, `.json`, Helm chart directories/archives, `.tgz` | Parse rendered manifests too; account for Helm values and Kustomize overlays. |
| OpenStack Heat | `.yaml`, `.yml`, `.json` | Parse HOT templates and intrinsic functions. |
| Pulumi | `Pulumi.yaml`, supported deployment JSON/export files | Prioritize structured deployment exports; language source scanning is an additional static-analysis capability. |
| Ansible / cloud-init | `.yaml`, `.yml`, `.json`, cloud-init user-data | Parse playbooks/user-data in a separate scanner family. |
| Policy files | Rego `.rego`, Azure Policy JSON, OPA bundles, Sentinel policies | Scan policy quality and evaluate policies against normalized resource graph when safe and deterministic. |

Accept ZIP/TAR/GZIP project archives only after safe archive inspection. Preserve relative paths and module boundaries. Do not accept arbitrary executable packages as config input.

### 3.2 Do not silently process these as ordinary config

- Credential files: AWS credentials/config, Azure service-principal JSON, GCP service-account keys, OCI API private keys, IBM API keys, Tencent/Huawei credentials, SSH private keys.
- Terraform provider cache, plugin binaries, `.terraform/` directories.
- Terraform state containing secrets, unless an explicit high-risk state-import workflow is enabled.
- Untrusted scripts, shell hooks, provisioners, external data sources, or arbitrary local-exec code.
- Encrypted files for which no safe customer-controlled decryption path exists.

Use a dedicated secrets scanner before parsers. If credentials are found, do not echo them in findings; mask the value and recommend rotation when there is evidence they may have been exposed.

---

## 4. Sample configuration fixtures

The following fixtures are **deliberately insecure test inputs** so the product can prove that its rules detect common failures. They are not production examples and must never be deployed. Store them in a test-fixture directory with a `DO_NOT_DEPLOY` marker. Keep a matching secure fixture for each provider and test both pass and fail behavior.

### 4.1 AWS — CloudFormation YAML (`aws-insecure.yaml`)

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: DO_NOT_DEPLOY - intentionally insecure scanner fixture
Resources:
  PublicBucket:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: false
        IgnorePublicAcls: false
        BlockPublicPolicy: false
        RestrictPublicBuckets: false
  OpenSshSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: DO_NOT_DEPLOY - public SSH test
      VpcId: vpc-0123456789abcdef0
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
```

Expected findings: unrestricted SSH ingress; S3 public-access protections disabled. Add rules for missing encryption, access logging, CloudTrail coverage, IAM wildcards and public database exposure in separate fixtures so each rule can be tested independently.

### 4.2 AWS — Terraform HCL (`aws-insecure.tf`)

```hcl
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = "ap-south-1"
}

resource "aws_security_group" "public_admin" {
  name        = "DO_NOT_DEPLOY-public-admin"
  description = "Intentionally insecure scanner fixture"
  ingress {
    description = "Unrestricted SSH - intentionally insecure"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "test_bucket" {
  bucket = "replace-with-globally-unique-test-name"
}

resource "aws_s3_bucket_public_access_block" "test_bucket" {
  bucket                  = aws_s3_bucket.test_bucket.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
```

Expected findings: SSH open to the Internet; bucket public-access protections disabled. Static scanner must not attempt to contact AWS or deploy these resources.

### 4.3 Microsoft Azure — Bicep (`azure-insecure.bicep`)

```bicep
// DO_NOT_DEPLOY - intentionally insecure scanner fixture
param location string = 'centralindia'

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'stexampleinsecure001'
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    allowBlobPublicAccess: true
    minimumTlsVersion: 'TLS1_0'
    publicNetworkAccess: 'Enabled'
    supportsHttpsTrafficOnly: false
  }
}

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: 'DO_NOT_DEPLOY-open-ssh'
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowSSHFromInternet'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
        }
      }
    ]
  }
}
```

Expected findings: public blob access allowed; weak TLS minimum; HTTPS-only disabled; public network access enabled (severity depends on data/service exposure); unrestricted SSH from any source. Check API versions against the current Azure resource reference before using as a compiler fixture.

### 4.4 Microsoft Azure — ARM JSON (`azure-insecure.json`)

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "metadata": { "purpose": "DO_NOT_DEPLOY - scanner fixture" },
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2023-05-01",
      "name": "stexampleinsecure002",
      "location": "centralindia",
      "sku": { "name": "Standard_LRS" },
      "kind": "StorageV2",
      "properties": {
        "allowBlobPublicAccess": true,
        "minimumTlsVersion": "TLS1_0",
        "publicNetworkAccess": "Enabled",
        "supportsHttpsTrafficOnly": false
      }
    }
  ]
}
```

Expected findings: same storage checks as the Bicep example. The ARM and Bicep scanners should produce normalized findings with source file/line references.

### 4.5 Google Cloud — Terraform (`gcp-insecure.tf`)

```hcl
terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
  }
}

provider "google" {
  project = "replace-with-test-project-id"
  region  = "asia-south1"
}

resource "google_compute_firewall" "public_ssh" {
  name    = "do-not-deploy-public-ssh"
  network = "default"
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["0.0.0.0/0"]
}

resource "google_storage_bucket" "public_bucket" {
  name                        = "replace-with-globally-unique-test-name"
  location                    = "ASIA-SOUTH1"
  uniform_bucket_level_access = false
}

resource "google_storage_bucket_iam_member" "public_reader" {
  bucket = google_storage_bucket.public_bucket.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
```

Expected findings: public SSH ingress; public object read; uniform bucket-level access disabled. Add checks for public IPs, service-account key creation, primitive roles, default networks, audit log exclusions and CMEK requirements.

### 4.6 Oracle Cloud Infrastructure — Terraform (`oci-insecure.tf`)

```hcl
terraform {
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = "~> 7.0"
    }
  }
}

provider "oci" {
  region = "ap-mumbai-1"
}

variable "compartment_ocid" {
  type        = string
  description = "Synthetic test value; replace only in an isolated test environment"
}

resource "oci_core_security_list" "open_ssh" {
  compartment_id = var.compartment_ocid
  vcn_id         = "ocid1.vcn.oc1.ap-mumbai-1.synthetic"
  display_name   = "DO_NOT_DEPLOY_open_ssh"

  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options {
      min = 22
      max = 22
    }
  }
}

resource "oci_objectstorage_bucket" "public_bucket" {
  compartment_id = var.compartment_ocid
  namespace      = "replace-with-object-storage-namespace"
  name           = "do-not-deploy-public-bucket"
  access_type    = "ObjectRead"
}
```

Expected findings: unrestricted SSH; public object-read bucket. Synthetic OCIDs mean this fixture is for parser/rule testing only. Verify the exact resource argument names against the pinned OCI provider schema.

### 4.7 Alibaba Cloud — ROS YAML (`aliyun-insecure.yaml`)

```yaml
ROSTemplateFormatVersion: '2015-09-01'
Description: DO_NOT_DEPLOY - intentionally insecure scanner fixture
Parameters:
  VpcId:
    Type: String
    Description: Synthetic VPC ID for static analysis only
Resources:
  OpenSshIngress:
    Type: ALIYUN::ECS::SecurityGroupIngress
    Properties:
      SecurityGroupId: sg-synthetic-do-not-deploy
      IpProtocol: tcp
      PortRange: 22/22
      SourceCidrIp: 0.0.0.0/0
      NicType: intranet
Outputs:
  FixturePurpose:
    Value: Static scanner test only; do not deploy
```

Expected finding: SSH allowed from all IPv4 addresses. This is a resource-level ROS fixture; validate required properties and resource type support against the current ROS resource specification before promoting it to a parser golden test. ROS supports JSON/YAML templates and hosted Terraform workflows.

### 4.8 IBM Cloud — Terraform (`ibm-insecure.tf`)

```hcl
terraform {
  required_providers {
    ibm = {
      source  = "IBM-Cloud/ibm"
      version = ">= 1.87.0"
    }
  }
}

provider "ibm" {
  region = "eu-gb"
}

resource "ibm_is_vpc" "test" {
  name = "do-not-deploy-test-vpc"
}

resource "ibm_is_security_group" "test" {
  name = "do-not-deploy-public-ssh"
  vpc  = ibm_is_vpc.test.id
}

resource "ibm_is_security_group_rule" "public_ssh" {
  group     = ibm_is_security_group.test.id
  direction = "inbound"
  remote    = "0.0.0.0/0"
  name      = "intentionally-insecure-ssh"
  protocol  = "tcp"
  port_min  = 22
  port_max  = 22
}
```

Expected finding: unrestricted inbound SSH. Keep provider version pinned and validate this file with `terraform validate` in a no-credentials sandbox; it must not be applied.

### 4.9 Tencent Cloud — Terraform (`tencent-insecure.tf`)

```hcl
terraform {
  required_providers {
    tencentcloud = {
      source  = "tencentcloudstack/tencentcloud"
      version = "~> 1.0"
    }
  }
}

provider "tencentcloud" {
  region = "ap-mumbai"
}

resource "tencentcloud_security_group" "test" {
  name        = "DO_NOT_DEPLOY-public-ssh"
  description = "Intentionally insecure scanner fixture"
}

resource "tencentcloud_security_group_rule_set" "test" {
  security_group_id = tencentcloud_security_group.test.id

  ingress {
    action      = "ACCEPT"
    cidr_block  = "0.0.0.0/0"
    protocol    = "TCP"
    port        = "22"
    description = "Unrestricted SSH - intentionally insecure"
  }
}
```

Expected finding: unrestricted SSH. Tencent provider rule-set semantics and region availability must be validated against the pinned provider and account regions.

### 4.10 Huawei Cloud — Terraform (`huawei-insecure.tf`)

```hcl
terraform {
  required_providers {
    huaweicloud = {
      source  = "huaweicloud/huaweicloud"
      version = ">= 1.36.0"
    }
  }
}

provider "huaweicloud" {
  region = "ap-southeast-3"
}

resource "huaweicloud_networking_secgroup" "test" {
  name                = "DO_NOT_DEPLOY-public-ssh"
  delete_default_rules = true
}

resource "huaweicloud_networking_secgroup_rule" "public_ssh" {
  security_group_id = huaweicloud_networking_secgroup.test.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = "0.0.0.0/0"
}
```

Expected finding: unrestricted SSH. Region and resource availability vary; verify with current Huawei provider docs. Do not place real access/secret keys in the fixture.

### 4.11 DigitalOcean — Terraform (`digitalocean-insecure.tf`)

```hcl
terraform {
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

provider "digitalocean" {}

resource "digitalocean_droplet" "test" {
  name   = "do-not-deploy-test"
  size   = "s-1vcpu-1gb"
  image  = "ubuntu-24-04-x64"
  region = "blr1"
}

resource "digitalocean_firewall" "open_ssh" {
  name        = "DO_NOT_DEPLOY-open-ssh"
  droplet_ids = [digitalocean_droplet.test.id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
}
```

Expected finding: SSH open to all IPv4 and IPv6 sources. If region/image values are not available in an account, static scanning should still parse and report the rule.

### 4.12 Akamai Connected Cloud / Linode — Terraform (`linode-insecure.tf`)

```hcl
terraform {
  required_providers {
    linode = {
      source  = "linode/linode"
      version = "~> 3.0"
    }
  }
}

provider "linode" {}

resource "linode_firewall" "open_ssh" {
  label = "DO_NOT_DEPLOY-open-ssh"

  inbound {
    protocol  = "TCP"
    ports     = ["22"]
    addresses = ["0.0.0.0/0", "::/0"]
  }
}
```

Expected finding: unrestricted SSH. Test whether the firewall is attached to compute instances in the normalized relationship graph; an unattached firewall rule is not the same as an effective exposure.

### 4.13 Hetzner Cloud — Terraform (`hetzner-insecure.tf`)

```hcl
terraform {
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.0"
    }
  }
}

provider "hcloud" {}

resource "hcloud_firewall" "open_ssh" {
  name = "DO_NOT_DEPLOY-open-ssh"

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
}
```

Expected finding: SSH open globally. Also check whether firewall is actually applied to one or more servers; model the `apply_to` relationship when present.

### 4.14 Vultr — Terraform (`vultr-insecure.tf`)

```hcl
terraform {
  required_providers {
    vultr = {
      source  = "vultr/vultr"
      version = "~> 2.0"
    }
  }
}

provider "vultr" {}

resource "vultr_firewall_group" "test" {
  description = "DO_NOT_DEPLOY - scanner fixture"
}

resource "vultr_firewall_rule" "public_ssh" {
  firewall_group_id = vultr_firewall_group.test.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "22"
  notes             = "Unrestricted SSH - intentionally insecure"
}
```

Expected finding: SSH open to all IPv4 addresses. The `subnet_size = 0` fixture is based on the provider's CIDR-style rule model; validate with the pinned provider before using as a CI golden file.

### 4.15 OVHcloud — Terraform (`ovhcloud-sample.tf`)

```hcl
terraform {
  required_providers {
    ovh = {
      source  = "ovh/ovh"
      version = "~> 2.0"
    }
  }
}

provider "ovh" {
  endpoint = "ovh-eu"
}

# Minimal provider-specific resource fixture. Network resources are
# represented here to test provider identification and resource extraction.
resource "ovh_cloud_project_network_private" "test" {
  service_name = "synthetic-project-id"
  name         = "DO_NOT_DEPLOY-private-network"
  regions      = ["GRA11"]
}
```

This is a provider-identification/resource-inventory fixture, not an insecure rule fixture. Add OVHcloud firewall/security-group rules only after validating the current supported resource model and API behavior. Do not invent rule semantics based on another provider.

### 4.16 Scaleway — Terraform (`scaleway-insecure.tf`)

```hcl
terraform {
  required_providers {
    scaleway = {
      source  = "scaleway/scaleway"
    }
  }
  required_version = ">= 1.0.0"
}

provider "scaleway" {
  zone   = "fr-par-1"
  region = "fr-par"
}

resource "scaleway_instance_security_group" "open_ssh" {
  name                    = "DO_NOT_DEPLOY-open-ssh"
  inbound_default_policy  = "drop"
  outbound_default_policy = "accept"

  inbound_rule {
    action   = "accept"
    port     = "22"
    ip_range = "0.0.0.0/0"
  }
}
```

Expected finding: SSH accepted from all IPv4 sources. Add the IPv6 counterpart in a separate fixture if the provider schema supports it. Check the current provider version and rule schema.

### 4.17 UpCloud — Terraform (`upcloud-insecure.tf`)

```hcl
terraform {
  required_providers {
    upcloud = {
      source  = "UpCloudLtd/upcloud"
      version = "~> 5.0"
    }
  }
}

provider "upcloud" {}

resource "upcloud_firewall_rules" "open_ssh" {
  server_id = "synthetic-server-id"

  firewall_rule {
    action                 = "accept"
    comment                = "DO_NOT_DEPLOY - unrestricted SSH"
    destination_port_start = "22"
    destination_port_end   = "22"
    direction              = "in"
    family                 = "IPv4"
    protocol               = "tcp"
    source_address_start   = "0.0.0.0"
    source_address_end     = "255.255.255.255"
  }
}
```

Expected finding: SSH accepted from the full IPv4 range. Validate the provider's address-range semantics and schema in the pinned version.

### 4.18 OpenStack — Terraform (`openstack-insecure.tf`)

```hcl
terraform {
  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 3.0"
    }
  }
}

provider "openstack" {}

resource "openstack_networking_secgroup_v2" "test" {
  name        = "DO_NOT_DEPLOY-public-ssh"
  description = "Intentionally insecure scanner fixture"
}

resource "openstack_networking_secgroup_rule_v2" "public_ssh" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.test.id
}
```

Expected finding: unrestricted SSH. Private cloud distributors often extend OpenStack; identify vendor extensions and mark unparsed properties rather than dropping them.

### 4.19 Kubernetes — manifest (`k8s-insecure.yaml`)

```yaml
# DO_NOT_DEPLOY - intentionally insecure Kubernetes fixture
apiVersion: v1
kind: Pod
metadata:
  name: do-not-deploy-privileged
  namespace: default
spec:
  hostNetwork: true
  containers:
    - name: test
      image: nginx:latest
      securityContext:
        privileged: true
        allowPrivilegeEscalation: true
        runAsUser: 0
        capabilities:
          add: ["ALL"]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all
  namespace: default
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
  ingress:
    - {}
  egress:
    - {}
```

Expected findings: privileged container; root user; privilege escalation; all Linux capabilities; host networking; no traffic restriction / allow-all network policy. Evaluate Kubernetes separately from the underlying cloud account.

---

## 5. Security checks the cloud module should implement

Build rules at the normalized resource level, but retain provider-specific rule implementations and evidence. The list below is a starting catalogue, not an assertion that every provider exposes every control through IaC.

### 5.1 Identity and access management

- Root/owner account has MFA; no permanent access keys where avoidable.
- No wildcard administrative permissions (`*:*`, Owner, primitive Owner/Editor roles, broad `Action: *`) unless a documented exception exists.
- Avoid public/anonymous principals and unauthenticated trust policies.
- Enforce least privilege, scoped roles, separation of duties and short-lived credentials.
- Restrict cross-account/project/tenant trust; validate external IDs and workload identity federation.
- Detect unused/orphaned identities, service-account keys, access keys and long-lived secrets (live API required for usage age).
- Detect privilege escalation paths and overly broad role assignment at account, organization, project, subscription, folder and resource scopes.

### 5.2 Network exposure and segmentation

- Flag `0.0.0.0/0` and `::/0` to management ports: SSH 22, RDP 3389, WinRM 5985/5986, database ports and administrative interfaces.
- Flag all-protocol/all-port ingress from the Internet.
- Detect default-allow security groups, permissive network ACLs, public IPs on sensitive workloads, public control-plane endpoints and missing private endpoints.
- Build effective exposure relationships: Internet gateway/public IP → route table → firewall/NSG/security group → interface/instance/service. Do not flag a disconnected rule as a confirmed live exposure without topology evidence.
- Detect missing network segmentation between production, development, management, data and backup zones.
- Detect unrestricted egress and risky outbound paths; severity should consider destination, protocol and resource role.
- Identify missing DDoS/WAF protections where applicable and supported by the chosen policy baseline.

### 5.3 Storage and data protection

- Detect public buckets/containers, public ACLs, anonymous listing/read/write, and overly broad bucket/container policies.
- Require encryption at rest and TLS in transit; prefer customer-managed keys when mandated by the selected policy.
- Detect weak/disabled key rotation, unprotected key deletion, overly broad key policies and missing key separation.
- Detect missing access logging, object versioning, retention/immutability and backup protection when required.
- Detect database public endpoints, weak TLS, unencrypted storage/backups, broad network access and missing audit logs.
- Detect exposed snapshots, images, backups, disks and managed database exports.

### 5.4 Logging, monitoring and incident readiness

- Detect missing organization-wide or account-wide audit trails.
- Ensure management/control-plane activity is logged and protected from deletion or tampering.
- Detect missing central log destination, retention, encryption, access controls and alerting.
- Check security findings integrations, threat detection, configuration history and incident notification paths.
- Detect disabled logging selectors, excluded event types, unmonitored regions/projects/subscriptions and broken log delivery.
- Verify log retention and immutability from live API or explicit retention-resource configuration; don't infer actual log delivery from a destination field alone.

### 5.5 Compute, images and workload configuration

- Detect public admin access, unencrypted boot/data volumes, disabled secure boot/vTPM where supported, outdated/unsafe machine images when version data is available, and missing instance metadata protections.
- Detect weak metadata service settings (e.g., IMDSv1 where applicable), unprotected instance identities and overprivileged workload roles.
- Detect exposed management ports, privileged containers, root execution, host PID/network/IPC, added capabilities, writable root filesystem, missing resource limits and unpinned images.
- Identify unencrypted snapshots, backups and persistent volumes.
- Separate configuration checks from image/package vulnerability scanning; the latter requires image or artifact scanning.

### 5.6 Managed services and platform controls

- Databases: private network access, TLS, encryption, audit logging, backups, retention, automated patching and least-privilege database identities.
- Kubernetes: API endpoint exposure, authorized networks, RBAC, audit logs, admission controls, encryption at rest, workload identity, node security, network policies and pod security.
- Load balancers/API gateways: TLS policy, certificates, access logs, WAF policy, backend encryption, health checks and public listener exposure.
- DNS: DNSSEC where applicable, protected zones, controlled record updates and logging.
- Secrets managers: rotation, access policies, private access and audit events.
- Serverless: public invocation policy, execution role permissions, secret handling, VPC/network attachment where needed, event-source trust and logging.

### 5.7 Secrets and sensitive data in uploads

- Scan for cloud access keys, private keys, tokens, passwords, connection strings and embedded certificates.
- Mask secrets in UI and report output. Never place a secret value into an LLM prompt unless the product has an explicit approved data-handling path.
- Hash or fingerprint a secret only when needed for deduplication; don't store the raw value in findings.
- Warn that a secret in a customer-uploaded file may require rotation even if the file was never deployed.

---

## 6. Compliance and control mapping

### 6.1 Frameworks / baselines

| Framework / baseline | How to use it in this product | What static upload can prove |
|---|---|---|
| CIS Benchmarks | Provider-specific technical configuration baseline. Pin exact version, level and profile. | Many resource settings can be tested. Organization-wide/live controls may remain unknown. |
| CIS Controls v8.1 | Higher-level security safeguard mapping and reporting layer. | A configuration result may contribute evidence but rarely proves the entire safeguard. |
| NIST CSF 2.0 | Outcome-oriented mapping for Govern, Identify, Protect, Detect, Respond and Recover. | Map technical evidence to outcomes; do not call it a CSF certification. |
| NIST SP 800-53 Rev. 5 | Control catalogue and assessment mapping; select customer-defined baseline. | Configuration may support selected controls, not organizational/process controls. |
| ISO/IEC 27001:2022 | Annex A control evidence mapping; customer scope and Statement of Applicability matter. | IaC can provide technical evidence for selected controls but cannot prove an ISO audit or certification. |
| PCI DSS 4.0.1 | Map applicable technical requirements to assets and cardholder-data environment. | Upload-only cannot determine scope, compensating controls, operational evidence or full compliance. |
| SOC 2 | Map to applicable Trust Services Criteria and customer evidence. | Technical settings are partial evidence only; SOC 2 is an attestation, not a simple config score. |
| HIPAA Security Rule | Map relevant safeguards where applicable to the covered entity/business associate context. | Configuration does not prove policies, risk analysis, workforce training, BAAs or full HIPAA compliance. |
| GDPR | Map technical measures relevant to security of processing and privacy controls. | Configuration cannot establish lawful basis, notices, data subject rights, DPIAs or complete GDPR compliance. |
| DISA STIG | Apply only to relevant cloud workloads/OS/platforms with the correct STIG release. | Cloud-control-plane settings alone do not prove host/OS hardening. |

CIS publishes cloud-provider benchmarks for AWS, Azure, GCP, OCI, Alibaba Cloud and IBM Cloud. The exact benchmark edition changes; read and pin the edition at rule-pack build time. Do not invent equivalent CIS benchmark IDs for Tencent, Huawei or smaller providers when none is verified.

### 6.2 Rule metadata required

Every rule should contain:

```yaml
id: CLOUD-AWS-SG-SSH-001
name: Security group must not expose SSH to the Internet
provider: aws
resource_types:
  - AWS::EC2::SecurityGroup
  - aws_security_group
category: network_exposure
severity: high
assessment_mode: static_and_live
logic_version: 1.0.0
framework_mappings:
  - framework: CIS-AWS-Foundations
    version: "PINNED-BENCHMARK-VERSION"
    control_id: "VERIFY-EXACT-CONTROL-ID"
  - framework: NIST-800-53
    version: "Rev. 5"
    control_id: "SC-7"

logic_summary: Ingress for TCP port 22 must not allow 0.0.0.0/0 or ::/0.
unknown_handling: unknown_if_source_or_port_is_dynamic
remediation:
  summary: Restrict SSH to an approved administrative CIDR or use a managed access service.
references:
  - https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html
```

Do not copy placeholder mappings into a production compliance pack. A compliance mapping must be checked against the licensed/current benchmark edition and exact control text before being marked verified.

### 6.3 Compliance score design

- Compute results per framework, benchmark version, scope, and assessment mode.
- Report `Passed`, `Failed`, `Unknown`, `Not Applicable`, and `Not Assessed` separately.
- Never count unknown or not-assessed controls as passed.
- Show control coverage denominator and evidence completeness.
- Allow customer-defined applicability and documented exceptions with owner, justification, expiry and approval.
- Avoid one misleading global percentage across different frameworks or benchmark editions.

---

## 7. Recommended scanning architecture

```text
Upload / Read-only Connector
           |
           v
File-type + Provider Detection
           |
           v
Archive Safety + Secret Scan
           |
           v
Format-specific Parsers / Compilers
(Terraform, CloudFormation, ARM/Bicep, ROS, K8s, Heat ...)
           |
           v
Provider Resource IR + Provenance
           |
           +--------------------+
           |                    |
           v                    v
Provider-specific rules     Cross-cloud rules
           |                    |
           +---------+----------+
                     v
             Relationship Graph
                     |
                     v
       Compliance mapping / Evidence engine
                     |
                     v
    Findings + unknowns + remediation + report
                     |
                     v
          Optional read-only live assessment
                     |
                     v
      Drift / conflict / live evidence update
```

### 7.1 Parsers and scanner tools to evaluate

Use established scanners as independent engines and build a proprietary provider-normalization and evidence layer around them. Do not assume a single tool covers every cloud/provider/resource.

- **Checkov:** IaC misconfiguration/policy scanning across Terraform, CloudFormation, Kubernetes, Helm, ARM and related formats. Evaluate its provider coverage and graph policies.
- **Trivy config:** IaC misconfiguration scanning across Terraform, CloudFormation, ARM, Kubernetes, Helm and additional config types; also provides secret scanning. Check current coverage for each file type/version.
- **KICS:** IaC static analysis with many query packs; verify current supported platforms because older marketing pages may list formats no longer present in current docs.
- **OPA / Rego:** Custom policy-as-code engine for normalized IR and graph relationships.
- **Provider-native validation:** CloudFormation validate/lint; Bicep build/lint; `terraform fmt` / `terraform validate` with pinned providers; ROS validation; provider schema checks. Run offline where possible; do not deploy or execute arbitrary user code.

Example local scanning commands (execute only inside isolated, resource-limited workers):

```bash
# Trivy: scan an extracted IaC fixture directory
trivy config --severity HIGH,CRITICAL ./extracted-iac

# Checkov: scan IaC files
checkov -d ./extracted-iac --quiet

# KICS: scan IaC files
kics scan -p ./extracted-iac -o json --output-path ./scanner-output
```

Normalize external-tool outputs into the platform's schema. Track scanner name/version, query/rule ID, raw output reference, and deduplication key.

### 7.2 Normalized Cloud Resource IR

Minimum resource fields:

```json
{
  "resource_key": "aws:account-placeholder:ap-south-1:aws_security_group.web",
  "provider": "aws",
  "service": "ec2",
  "resource_type": "security_group",
  "logical_name": "web",
  "physical_id": null,
  "scope": {
    "organization": null,
    "account_or_tenant": null,
    "project_or_subscription": null,
    "region": "ap-south-1",
    "compartment_or_resource_group": null
  },
  "properties": {
    "ingress_rules": []
  },
  "relationships": [],
  "source": {
    "file": "main.tf",
    "line_start": 1,
    "line_end": 20,
    "format": "terraform_hcl",
    "provider_schema_version": "pinned-version",
    "parser_version": "parser-version"
  },
  "evidence_mode": "static",
  "confidence": 1.0,
  "unknown_fields": []
}
```

Preserve the original vendor resource type and properties in `provider_raw`; never discard provider-specific attributes during normalization. Normalize common concepts such as IAM principals/actions, network rules, storage public-access controls, encryption, logging, resource scope, keys, public endpoints, tags and relationships.

### 7.3 Relationship graph

Minimum entities: organization/account, project/subscription, region, VPC/VNet/VCN, subnet, route table, internet/NAT gateway, security group/NSG/firewall, NIC, public IP, VM/instance, bucket/storage account, key, database, load balancer, Kubernetes cluster/node/pod/service/network policy, IAM principal/role/policy, log destination.

Useful edges: `CONTAINS`, `ATTACHED_TO`, `ROUTES_TO`, `EXPOSES`, `PROTECTED_BY`, `GRANTS`, `ASSUMES_ROLE`, `ENCRYPTED_BY`, `LOGS_TO`, `PUBLICLY_ACCESSIBLE`, `DEPENDS_ON`, `MANAGED_BY`.

Every graph edge must carry provenance and certainty: `explicit`, `derived`, `inferred`, `live_observed`, `conflicting`, or `unknown`.

---

## 8. Upload pipeline and security requirements

The uploaded file is untrusted input. The parser itself is an attack surface.

1. Enforce maximum compressed and expanded sizes, file count, nesting depth, path length and processing time.
2. Protect against ZIP Slip, tar path traversal, symlink attacks, decompression bombs and archive recursion.
3. Detect file type by content as well as extension; reject executable/binary inputs unless explicitly supported.
4. Run parsing in ephemeral, unprivileged containers with read-only filesystem, CPU/memory/time limits and no cloud credentials.
5. Disable network access by default. Do not fetch Terraform modules, remote templates, provider binaries, external data sources, URLs or git repositories from user content during scan.
6. Do not execute `local-exec`, `remote-exec`, provisioners, shell scripts, arbitrary Python/Node code, Helm hooks or template functions with side effects.
7. Do not run `terraform init` against untrusted configurations in a network-connected worker. If provider schema resolution is required, use a pre-approved internal mirror and allow-listed versions in a separate sandbox.
8. Sanitize filenames and prevent cross-tenant path access.
9. Encrypt uploads and reports at rest and in transit; apply retention and deletion controls.
10. Tenant-isolate job queues, object storage paths, caches, logs, findings and temporary files.
11. Redact discovered credentials and private keys from all logs, traces and LLM context.
12. Protect report rendering against HTML/Markdown injection and oversized results.
13. Keep an immutable audit record of who uploaded, scanned, viewed, exported or deleted each artifact.

### 8.1 LLM usage boundaries

Use LLMs to explain findings, summarize architecture, propose remediation and assist with vendor-format interpretation. Do not make an LLM the sole authority for pass/fail compliance decisions. Rule execution must be deterministic, versioned and testable. Before sending user configuration to an external model, apply data minimization and secret redaction and respect customer data-residency/retention settings. LLM-generated remediations must be parsed, validated and shown as proposals; never auto-apply changes.

---

## 9. MVP implementation order

### Wave 1 — upload, parsing and baseline scanning

- Upload ZIP or individual files.
- Secure archive extraction and secret detection.
- Terraform HCL/JSON and plan JSON parser.
- CloudFormation YAML/JSON parser.
- Azure ARM parser and Bicep compilation.
- Kubernetes YAML/JSON parser.
- Integrate Checkov and Trivy; capture results in one schema.
- Build initial normalized IR and finding UI.

### Wave 2 — hyperscaler rule packs

- AWS, Azure and GCP resource model and rules.
- OCI and Alibaba ROS.
- IBM, Tencent and Huawei Terraform provider identification and initial security-group/storage/IAM rule coverage.
- CIS baseline mapping with pinned, verified editions.

### Wave 3 — alternatives and private cloud

- DigitalOcean, Akamai/Linode, Hetzner, Vultr, OVHcloud, Scaleway and UpCloud.
- OpenStack Heat and Terraform provider.
- VMware/NSX and Kubernetes advanced resource relations.
- Provider-specific rule and schema test packs.

### Wave 4 — live account evidence and drift

- Customer-authorized read-only connectors.
- Organization/account-wide inventory and effective policy resolution.
- Live audit/logging, encryption/key state, external exposure, IAM and resource configuration.
- Compare uploaded desired state to live state; report drift and conflicts.

### Wave 5 — compliance evidence and enterprise controls

- Framework-specific scoring with applicability, exceptions and evidence coverage.
- Historical snapshots, report exports, control ownership, remediation tracking and audit trail.
- Customer policy customization, private rule packs and on-prem deployment options.

---

## 10. Definition of done for each provider adapter

A provider is **not** supported merely because Terraform accepts its provider block or the scanner can identify `provider "x"`.

For every claimed provider/service/resource family, require:

- Provider/resource detection with correct provider and version.
- Parser/schema version pinned and upgrade tests.
- At least one passing and one failing fixture per implemented rule.
- Source-line evidence in findings.
- Unit tests for defaults, omitted fields, variables, locals, modules, expressions, loops/for_each/count, aliases, dynamic blocks and unknown/computed values as applicable.
- Resource relationships resolved and tested.
- Explicit coverage matrix: supported, partial, unsupported, unknown.
- Live API tests only when a read-only test account is available; otherwise clearly mark live assessment as untested.
- No deployment/apply during security scanning.
- Regression tests against a saved fixture corpus and current provider schemas.
- Documentation of unsupported resource types and known false positives/negatives.

Provider capability levels:

| Level | Meaning |
|---|---|
| P0 — identified | Detect provider/file format only |
| P1 — parsed | Parse resource declarations and source locations |
| P2 — normalized | Map supported resources to common IR |
| P3 — security rules | Tested security checks for documented resource families |
| P4 — compliance mapped | Exact, versioned benchmark/control mappings verified |
| P5 — live assessment | Read-only cloud API assessment with evidence |
| P6 — drift and graph | Cross-resource graph, effective exposure and static/live drift |

Expose the level per provider **and per resource family**, not just as one marketing badge.

---

## 11. Sample test cases for the first rule pack

| ID | Test case | Expected result |
|---|---|---|
| NET-001 | SSH TCP/22 from `0.0.0.0/0` | High severity fail |
| NET-002 | SSH TCP/22 from `::/0` | High severity fail |
| NET-003 | RDP TCP/3389 from all addresses | Critical/high fail depending on context |
| NET-004 | All protocols/all ports from Internet | Critical fail |
| NET-005 | Public database listener | Critical/high fail |
| IAM-001 | Public/anonymous principal grants read/write | Critical/high fail |
| IAM-002 | Wildcard administrator policy | High/critical fail depending on scope |
| IAM-003 | Resource assumes unrestricted cross-account role | High fail or unknown if dynamic |
| STO-001 | Bucket/container public access enabled | Critical/high fail depending on data context |
| STO-002 | Storage encryption disabled | High fail |
| STO-003 | TLS-only requirement disabled / weak minimum TLS | High fail |
| KEY-001 | Customer-managed key required but absent | Framework-dependent fail or unknown |
| LOG-001 | Organization-wide audit logging missing | High fail only when scope is known; otherwise unknown |
| LOG-002 | Audit trail not protected from deletion | High fail |
| DB-001 | Managed DB publicly accessible | High/critical fail |
| K8S-001 | Privileged container | High fail |
| K8S-002 | Container runs as root without approved exception | Medium/high fail |
| K8S-003 | No default-deny network segmentation | Framework/context dependent |
| SEC-001 | Credential or private key embedded in upload | Secret finding; redact value |
| CFG-001 | Dynamic expression hides security property | Unknown, never pass |
| CFG-002 | Firewall rule exists but is not attached to a workload | Do not claim effective exposure; retain rule finding with relationship caveat |

---

## 12. Output report requirements

The report should contain:

- Provider(s), detected file formats, provider/resource schema versions and scope.
- Assessment mode: upload-only or connected/live; exact data sources and timestamps.
- Summary counts by severity and evidence state.
- Findings with rule ID, description, severity, affected resource, source file/line, observed value, expected value, impact, confidence and evidence state.
- Framework mapping by exact version and control reference.
- Remediation recommendation and optional code patch/diff, clearly marked as un-applied.
- Unknown/not-assessed controls and why the product could not evaluate them.
- Coverage statement: resources parsed, resources unsupported, rules evaluated, and data not provided.
- Exceptions and compensating controls with expiry/owner.

Avoid labels such as "100% compliant", "certified", or "fully secure". Use precise language such as "No violations detected in the uploaded files for the selected rule pack; live cloud state and organizational controls were not assessed." 

---

## 13. Official documentation and reference links

Use these as starting points and re-check versioned docs at implementation time.

### Cloud provider IaC documentation

- [AWS CloudFormation template formats](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-formats.html)
- [AWS CloudFormation overview](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cloudformation-overview.html)
- [Azure ARM templates](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/)
- [Azure Bicep resource declarations](https://learn.microsoft.com/en-us/azure/azure-resource-manager/bicep/resource-declaration)
- [Google Cloud Terraform documentation](https://docs.cloud.google.com/docs/terraform)
- [Google Cloud Infrastructure Manager](https://cloud.google.com/infrastructure-manager/docs)
- [Google Cloud Deployment Manager deprecation](https://docs.cloud.google.com/deployment-manager/docs/deprecations)
- [OCI Resource Manager](https://docs.oracle.com/en-us/iaas/Content/ResourceManager/Concepts/resourcemanager.htm)
- [OCI Terraform provider](https://docs.oracle.com/en-us/iaas/tools/terraform-provider-oci/latest/)
- [Alibaba Cloud ROS quick start](https://www.alibabacloud.com/help/en/ros/getting-started)
- [IBM Cloud Schematics Terraform templates](https://cloud.ibm.com/docs/schematics?topic=schematics-create-tf-config)
- [Tencent Cloud Terraform provider](https://registry.terraform.io/providers/tencentcloudstack/tencentcloud/latest/docs)
- [Huawei Cloud Terraform provider](https://registry.terraform.io/providers/huaweicloud/huaweicloud/latest/docs)
- [DigitalOcean Terraform](https://docs.digitalocean.com/reference/terraform/)
- [Akamai/Linode Terraform and Cloud Firewall guide](https://www.akamai.com/cloud/guides/how-to-deploy-secure-linodes-using-cloud-firewalls-and-terraform)
- [Hetzner Cloud Terraform provider](https://registry.terraform.io/providers/hetznercloud/hcloud/latest/docs)
- [Vultr Terraform provider](https://registry.terraform.io/providers/vultr/vultr/latest/docs)
- [OVHcloud Terraform](https://www.ovhcloud.com/en/public-cloud/terraform/)
- [Scaleway Terraform quickstart](https://www.scaleway.com/en/docs/tutorials/terraform-quickstart/)
- [UpCloud Terraform provider](https://registry.terraform.io/providers/UpCloudLtd/upcloud/latest/docs)

### Security scanners and compliance references

- [Checkov](https://www.checkov.io/)
- [Trivy misconfiguration scanning](https://trivy.dev/docs/latest/guide/scanner/misconfiguration/)
- [Trivy IaC coverage](https://trivy.dev/docs/latest/coverage/iac/)
- [KICS documentation](https://docs.kics.io/latest/)
- [CIS Benchmarks catalog](https://www.cisecurity.org/cis-benchmarks)
- [CIS cloud benchmark list](https://resources.cisecurity.org/benchmarks)
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [NIST CSF informative references / mappings](https://www.nist.gov/cyberframework/informative-references)
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/a-security.html)
- [Azure Well-Architected security guidance](https://learn.microsoft.com/en-us/azure/well-architected/security/)
- [Google Cloud Well-Architected security pillar](https://docs.cloud.google.com/architecture/framework/security)

---

## 14. Implementation note for the assigned cloud engineer

Start with **Terraform/OpenTofu + CloudFormation + Azure ARM/Bicep + Kubernetes**, not 15 independent parsers. A large percentage of public-cloud providers can be reached through Terraform resources, while native templates should have dedicated parsers where semantics are provider-specific. Add ROS, Heat, and each alternative provider as tested adapters.

The core deliverable is not a list of supported extensions. It is a trustworthy pipeline that can say:

1. What cloud resources were declared?
2. What security properties are explicitly configured?
3. What relationships can be proven from the files?
4. Which security rules passed or failed?
5. Which compliance controls have evidence, and which remain unknown?
6. What additional live-cloud evidence is needed to make a stronger assessment?

**Non-negotiable:** Never execute customer deployments, never auto-remediate, never turn unknown into pass, and never make compliance claims beyond the evidence actually collected.
