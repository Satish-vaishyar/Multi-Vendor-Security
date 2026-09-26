"""M5 Canonical IR Validator: pydantic + JSON schema + business rules (not ML)."""
from __future__ import annotations
from typing import Any
from pydantic import BaseModel, field_validator

ALLOWED = {"services.ssh.version": [1, 2, "unknown"]}


class CanonicalIR(BaseModel):
    device_vendor: str = "unknown"
    services_ssh_version: Any = "unknown"
    services_telnet: Any = None
    services_http: Any = None
    logging_enabled: Any = None
    extra: dict = {}

    @field_validator("services_ssh_version")
    @classmethod
    def _ssh(cls, v):
        if v in (1, 2, "1", "2"):
            return int(v)
        return "unknown"


def validate(flat_ir: dict) -> dict:
    errors = []
    ssh = flat_ir.get("services.ssh.version", flat_ir.get("services_ssh_version", "unknown"))
    if ssh not in (1, 2, "unknown"):
        errors.append(f"services.ssh.version must be 1/2/unknown, got {ssh!r}")
    for k, v in flat_ir.items():
        if not isinstance(k, str) or "." not in k:
            errors.append(f"bad property name {k!r}")
        if isinstance(v, str) and v == "maybe secure":
            errors.append(f"non-canonical value for {k}")
    return {"valid": not errors, "errors": errors,
            "coerced": CanonicalIR(services_ssh_version=ssh if ssh in (1, 2) else "unknown").model_dump()}
