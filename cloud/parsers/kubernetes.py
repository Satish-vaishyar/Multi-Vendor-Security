"""Kubernetes manifest parser (RTM S10; CM-031, CM-058).

Reads rendered manifests (YAML/JSON, multi-document, `kind: List`). Helm templates and Kustomize overlays cannot be
rendered safely offline, so they are reported as `unrendered` (scan the output of `helm template` / `kustomize build`)
instead of being guessed at or executed.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Iterator, List, Optional, Tuple

from cloud import yamlutil
from cloud.ir import Resource, Source
from cloud.parsers.terraform import ParseResult

_PARSER = "cloud.parsers.kubernetes 1"
_POD_HOLDERS = {"Pod": ("spec",), "Deployment": ("spec", "template", "spec"), "StatefulSet": ("spec", "template", "spec"),
                "DaemonSet": ("spec", "template", "spec"), "ReplicaSet": ("spec", "template", "spec"),
                "Job": ("spec", "template", "spec"), "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
                "ReplicationController": ("spec", "template", "spec")}


def _group(api_version: str) -> str:
    return api_version.split("/", 1)[0] if "/" in api_version else "core"


def _docs(path: str, text: str, result: ParseResult) -> Iterator[Tuple[Any, int]]:
    try:
        docs = yamlutil.load_all(text)
    except yamlutil.YamlError as e:
        result.errors.append({"file": path, "error": f"invalid YAML/JSON: {e}"[:200]})
        return
    for d in docs:
        if isinstance(d, dict) and d.get("kind") == "List" and isinstance(d.get("items"), list):
            for item in d["items"]:
                yield item, yamlutil.line_of(item)
        else:
            yield d, yamlutil.line_of(d)


def parse_kubernetes(path: str, text: str) -> ParseResult:
    result = ParseResult()
    if "{{" in text and "}}" in text:
        result.unresolved_modules.append({"module": path, "source": path, "file": path,
                                          "reason": "Helm template not rendered offline; scan the output of 'helm template'"})
        return result
    for doc, line in _docs(path, text, result):
        if not isinstance(doc, dict) or "kind" not in doc or "apiVersion" not in doc:
            continue
        if doc["kind"] == "Kustomization":
            result.unresolved_modules.append({"module": path, "source": path, "file": path,
                                              "reason": "Kustomize overlay not built offline; scan the output of 'kustomize build'"})
            continue
        meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
        name = str(meta.get("name", "")) or "(unnamed)"
        ns = str(meta.get("namespace", "")) or "default"
        kind = str(doc["kind"])
        cluster_scoped = kind in ("Namespace", "ClusterRole", "ClusterRoleBinding", "PersistentVolume", "StorageClass",
                                  "CustomResourceDefinition", "PodSecurityPolicy", "Node")
        props = json.loads(json.dumps({k: v for k, v in doc.items()}, default=str))
        result.resources.append(Resource(
            provider="kubernetes", service=_group(str(doc["apiVersion"])), resource_type=kind, logical_name=name,
            address=f"{kind}/{name}" if cluster_scoped else f"{ns}/{kind}/{name}", properties=props,
            source=Source(path, line, line, "kubernetes", _PARSER), provider_raw=props,
            notes=[] if (ns != "default" or cluster_scoped or "namespace" in meta) else ["namespace not set: defaults to 'default'"],
        ).finalize())
    return result


def pod_spec(resource: Resource) -> Optional[Dict[str, Any]]:
    """The pod spec of a workload resource (Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob, ...), or None."""
    path = _POD_HOLDERS.get(resource.resource_type)
    if not path:
        return None
    node: Any = resource.properties
    for key in path:
        node = node.get(key) if isinstance(node, dict) else None
    return node if isinstance(node, dict) else None


def containers(spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    """All containers (regular, init, ephemeral) of a pod spec, each tagged with its list name."""
    out: List[Dict[str, Any]] = []
    for list_name in ("containers", "initContainers", "ephemeralContainers"):
        for c in spec.get(list_name) or []:
            if isinstance(c, dict):
                out.append({**c, "__list__": list_name})
    return out
