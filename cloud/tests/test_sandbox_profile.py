"""Locks in the scanner isolation model (RTM CM-103/104/156). These guard the compose overlay and Dockerfile."""
import pathlib
import re

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPOSE = yaml.safe_load((ROOT / "docker-compose.cloud.yml").read_text(encoding="utf-8"))
DOCKERFILE = (ROOT / "cloud" / "Dockerfile").read_text(encoding="utf-8")
SCANNER = COMPOSE["services"]["cloud-scanner"]


def test_scanner_is_unprivileged_and_read_only():
    assert SCANNER["read_only"] is True
    assert SCANNER["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in SCANNER["security_opt"]
    assert not SCANNER["user"].startswith("0") and SCANNER["user"] != "root"
    assert not SCANNER.get("privileged", False)
    assert SCANNER["pids_limit"] <= 256 and SCANNER["mem_limit"] and SCANNER["cpus"]


def test_scanner_has_no_secrets_ports_or_mounts():
    for forbidden in ("ports", "env_file", "volumes", "devices", "cap_add", "network_mode", "pid", "ipc"):
        assert forbidden not in SCANNER, forbidden
    assert "noexec" in SCANNER["tmpfs"][0]


def test_scanner_only_on_internal_network():
    assert SCANNER["networks"] == ["cloud_scan"]
    assert COMPOSE["networks"]["cloud_scan"]["internal"] is True


def test_only_backend_and_worker_join_the_scan_network():
    joined = {n for n, s in COMPOSE["services"].items() if "cloud_scan" in s.get("networks", [])}
    assert joined == {"cloud-scanner", "cloud-scheduler", "backend", "worker"}


def test_overlay_changes_nothing_but_the_flag_and_url_on_existing_services():
    for name in ("backend", "worker"):
        svc = COMPOSE["services"][name]
        assert set(svc) == {"environment", "networks"}
        assert set(svc["environment"]) == {"CLOUD_MODULE_ENABLED", "CLOUD_SCANNER_URL"}


def test_dockerfile_runs_as_non_root_without_remote_fetches():
    assert re.search(r"^USER 10001:10001$", DOCKERFILE, re.M)
    assert "ADD http" not in DOCKERFILE and "curl" not in DOCKERFILE
    assert "--frozen" in DOCKERFILE
    runtime = DOCKERFILE.split("AS runtime", 1)[1]
    assert "pip install" not in runtime and "uv " not in runtime   # no package managers in the runtime stage


def test_image_is_built_from_the_repo_root_with_only_the_module_files():
    build = SCANNER["build"]
    assert build["context"] == "." and build["dockerfile"] == "cloud/Dockerfile"
    ignore = (ROOT / "cloud" / "Dockerfile.dockerignore").read_text(encoding="utf-8").splitlines()
    assert ignore[:3] == ["*", "!cloud", "!okf-cloud"]            # everything else (backend/.env, frontend, .git) is excluded
    assert "COPY okf-cloud /srv/okf-cloud" in DOCKERFILE and "COPY cloud /srv/cloud" in DOCKERFILE
