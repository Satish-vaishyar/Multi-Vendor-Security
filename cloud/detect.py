"""Content-based file-format and provider detection (RTM S06; CM-102, CM-041).

Never trusts the extension alone. Pure functions over text; nothing is executed or fetched.
"""
from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from cloud import yamlutil

# Normalised provider identifiers used everywhere else in the module.
_TF_PROVIDER = {
    "aws": "aws", "azurerm": "azure", "azuread": "azure", "azapi": "azure", "google": "gcp", "google-beta": "gcp",
    "oci": "oci", "alicloud": "alibaba", "ibm": "ibm", "tencentcloud": "tencent", "huaweicloud": "huawei",
    "digitalocean": "digitalocean", "linode": "linode", "hcloud": "hetzner", "vultr": "vultr", "ovh": "ovh",
    "scaleway": "scaleway", "upcloud": "upcloud", "openstack": "openstack", "vsphere": "vmware", "nsxt": "vmware",
    "nutanix": "nutanix", "kubernetes": "kubernetes", "equinix": "equinix",
}
_RESOURCE_RE = re.compile(r'^\s*(?:resource|data)\s+"([A-Za-z0-9_]+)"\s+"[^"]+"', re.M)
_PROVIDER_RE = re.compile(r'^\s*provider\s+"([A-Za-z0-9_-]+)"', re.M)
_SOURCE_RE = re.compile(r'source\s*=\s*"([A-Za-z0-9_.-]+/)?([A-Za-z0-9_-]+)"')
_CFN_TYPE = re.compile(r"^(AWS|Alexa)::")


@dataclass
class Detection:
    path: str
    format: str                                   # see FORMATS
    providers: List[str] = field(default_factory=list)
    note: str = ""


FORMATS = ("terraform_hcl", "terraform_json", "terraform_plan", "terraform_state", "cloudformation", "arm", "bicep",
           "ros", "heat", "kubernetes", "helm_chart", "pulumi", "rego", "cloud_init", "ansible", "unknown")


def _add(out: List[str], provider: Optional[str]) -> None:
    if provider and provider not in out:
        out.append(provider)


def _tf_providers_from_types(types: List[str], out: List[str]) -> None:
    for t in types:
        _add(out, _TF_PROVIDER.get(t.split("_", 1)[0]))


def _hcl_providers(text: str) -> List[str]:
    out: List[str] = []
    for name in _PROVIDER_RE.findall(text):
        _add(out, _TF_PROVIDER.get(name))
    for _, name in _SOURCE_RE.findall(text):
        _add(out, _TF_PROVIDER.get(name))
    _tf_providers_from_types(_RESOURCE_RE.findall(text), out)
    return out


def _json_or_none(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return None


def _resource_types(data: Dict[str, Any]) -> List[str]:
    """'Type' values of a CloudFormation-style Resources mapping."""
    return [v.get("Type", "") for v in data["Resources"].values() if isinstance(v, dict)]


def _from_structured(path: str, data: Any) -> Optional[Detection]:
    if not isinstance(data, dict):
        return None
    if "AWSTemplateFormatVersion" in data or "Transform" in data or (
            isinstance(data.get("Resources"), dict)
            and any(_CFN_TYPE.match(t) for t in _resource_types(data))):
        return Detection(path, "cloudformation", ["aws"])
    if "ROSTemplateFormatVersion" in data:
        return Detection(path, "ros", ["alibaba"])
    if "heat_template_version" in data:
        return Detection(path, "heat", ["openstack"])
    schema = str(data.get("$schema", ""))
    if "deploymentTemplate" in schema or "subscriptionDeploymentTemplate" in schema or "tenantDeploymentTemplate" in schema:
        return Detection(path, "arm", ["azure"])
    if "format_version" in data and ("planned_values" in data or "resource_changes" in data or "configuration" in data):
        provs: List[str] = []
        rc = data.get("resource_changes")
        if isinstance(rc, list):
            _tf_providers_from_types([r.get("type", "") for r in rc if isinstance(r, dict)], provs)
        return Detection(path, "terraform_plan", provs)
    if "terraform_version" in data and "resources" in data and ("serial" in data or "lineage" in data):
        return Detection(path, "terraform_state", [], "contains secrets; opt-in required")
    if "kind" in data and "apiVersion" in data:
        return Detection(path, "kubernetes", ["kubernetes"])
    if "resource" in data or "provider" in data or "terraform" in data:
        provs = []
        res = data.get("resource")
        if isinstance(res, dict):
            _tf_providers_from_types(list(res), provs)
        if isinstance(data.get("provider"), dict):
            for name in data["provider"]:
                _add(provs, _TF_PROVIDER.get(name))
        return Detection(path, "terraform_json", provs)
    return None


def detect(path: str, text: str) -> Detection:
    """Classify one decoded file. `unknown` is a valid, non-fatal answer."""
    base = posixpath.basename(path).lower()
    if base.endswith((".bicep", ".bicepparam")):
        return Detection(path, "bicep", ["azure"])
    if base.endswith(".rego"):
        return Detection(path, "rego")
    if base in ("chart.yaml", "chart.yml"):
        return Detection(path, "helm_chart", ["kubernetes"])
    if base in ("pulumi.yaml", "pulumi.yml"):
        return Detection(path, "pulumi")
    if base.endswith((".tf", ".hcl", ".tfvars")):
        return Detection(path, "terraform_hcl", _hcl_providers(text))
    if text.lstrip().startswith("#cloud-config"):
        return Detection(path, "cloud_init")
    stripped = text.lstrip()
    if stripped[:1] in "{[":
        data = _json_or_none(text)
        found = _from_structured(path, data)
        if found:
            return found
        return Detection(path, "unknown")
    if base.endswith((".yaml", ".yml", ".template")):
        try:
            docs = yamlutil.load_all(text)
        except yamlutil.YamlError:
            return Detection(path, "unknown", note="invalid YAML")
        for doc in docs:
            found = _from_structured(path, doc)
            if found:
                return found
        if docs and all(isinstance(d, list) for d in docs):
            if any(isinstance(t, dict) and ("tasks" in t or "hosts" in t or "roles" in t) for d in docs for t in d):
                return Detection(path, "ansible")
    return Detection(path, "unknown")


def detect_all(files: List[Dict[str, str]]) -> List[Detection]:
    """files: [{'path':..., 'text':...}]"""
    return [detect(f["path"], f["text"]) for f in files]


def providers_of(detections: List[Detection]) -> List[str]:
    out: List[str] = []
    for d in detections:
        for p in d.providers:
            _add(out, p)
    return out
