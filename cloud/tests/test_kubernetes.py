import json

from cloud.parsers.kubernetes import containers, parse_kubernetes, pod_spec

K8S = """\
# DO_NOT_DEPLOY
apiVersion: v1
kind: Pod
metadata:
  name: priv
  namespace: default
spec:
  hostNetwork: true
  containers:
    - name: test
      image: nginx:latest
      securityContext: {privileged: true, runAsUser: 0}
  initContainers:
    - name: init
      image: busybox
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: allow-all}
spec: {podSelector: {}, policyTypes: [Ingress, Egress], ingress: [{}], egress: [{}]}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: prod}
spec:
  template:
    spec:
      containers: [{name: c, image: x}, "junk"]
      ephemeralContainers: [{name: e}]
---
apiVersion: batch/v1
kind: CronJob
metadata: {name: cj}
spec: {jobTemplate: {spec: {template: {spec: {containers: [{name: j}]}}}}}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: admin}
---
apiVersion: v1
kind: Service
---
just: data
"""


def test_kubernetes_manifests_multi_document():
    r = parse_kubernetes("k8s.yaml", K8S)
    assert r.errors == []
    pod, netpol, dep, cj, role, svc = r.resources
    assert pod.address == "default/Pod/priv" and pod.provider == "kubernetes" and pod.service == "core"
    assert netpol.service == "networking.k8s.io" and netpol.notes == ["namespace not set: defaults to 'default'"]
    assert dep.address == "prod/Deployment/web" and role.address == "ClusterRole/admin" and role.notes == []
    assert svc.logical_name == "(unnamed)"
    assert pod.source.line_start == 1 or pod.source.line_start > 0
    assert pod.properties["spec"]["hostNetwork"] is True


def test_pod_spec_and_containers_helpers():
    pod, netpol, dep, cj, *_ = parse_kubernetes("k8s.yaml", K8S).resources
    assert pod_spec(pod)["hostNetwork"] is True and pod_spec(netpol) is None
    assert [c["name"] for c in containers(pod_spec(pod))] == ["test", "init"]
    assert [(c["name"], c["__list__"]) for c in containers(pod_spec(dep))] == [("c", "containers"), ("e", "ephemeralContainers")]
    assert containers(pod_spec(cj))[0]["name"] == "j"
    bare = parse_kubernetes("d.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: d}\nspec: oops\n").resources[0]
    assert pod_spec(bare) is None


def test_kubernetes_list_json_and_unrenderable_inputs():
    lst = {"apiVersion": "v1", "kind": "List", "items": [
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "a", "namespace": "x"}}]}
    r = parse_kubernetes("l.json", json.dumps(lst))
    assert [x.address for x in r.resources] == ["x/ConfigMap/a"]
    helm = parse_kubernetes("templates/deploy.yaml", "image: {{ .Values.image }}\nkind: Deployment\n")
    assert helm.resources == [] and "helm template" in helm.unresolved_modules[0]["reason"]
    kust = parse_kubernetes("kustomization.yaml", "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources: [a.yaml]\n")
    assert kust.resources == [] and "kustomize build" in kust.unresolved_modules[0]["reason"]
    assert parse_kubernetes("bad.yaml", "a: [unclosed").errors[0]["error"].startswith("invalid YAML")
    assert parse_kubernetes("meta.yaml", "apiVersion: v1\nkind: Pod\nmetadata: oops\n").resources[0].logical_name == "(unnamed)"
