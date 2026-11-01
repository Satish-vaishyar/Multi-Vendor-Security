import io
import zipfile

from cloud import pipeline

STACK = '''
terraform {
  required_providers {
    oci = { source = "oracle/oci" }
  }
}
resource "oci_core_security_list" "open" {
  compartment_id = var.compartment
  vcn_id         = var.vcn
  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options {
      min = 22
      max = 22
    }
  }
}
resource "oci_core_security_list" "closed" {
  compartment_id = var.compartment
  vcn_id         = var.vcn
  ingress_security_rules {
    protocol = "6"
    source   = "10.0.0.0/8"
    tcp_options {
      min = 22
      max = 22
    }
  }
}
resource "oci_core_network_security_group_security_rule" "ssh" {
  network_security_group_id = "nsg"
  direction = "INGRESS"
  protocol  = "6"
  source    = "0.0.0.0/0"
  tcp_options {
    destination_port_range {
      min = 22
      max = 22
    }
  }
}
resource "oci_objectstorage_bucket" "pub" {
  compartment_id = var.compartment
  namespace      = "ns"
  name           = "b"
  access_type    = "ObjectRead"
}
'''


def zip_of(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for n, c in files.items():
            zf.writestr(n, c)
    return buf.getvalue()


def test_oci_resource_manager_zip_gives_pass_and_fail_with_lines(tmp_path):
    rep = pipeline.run_scan(zip_of({"stack/main.tf": STACK}), "stack.zip", tmp_path, salt=b"s")
    got = {(f["control_id"], f["resource_address"]): f["evidence_state"] for f in rep["findings"]}
    assert got[("CLOUD-NET-001", "oci_core_security_list.open")] == "FAIL_STATIC"
    assert got[("CLOUD-NET-001", "oci_core_security_list.closed")] == "PASS_STATIC"
    assert got[("CLOUD-NET-001", "oci_core_network_security_group_security_rule.ssh")] == "FAIL_STATIC"
    assert got[("CLOUD-STO-001", "oci_objectstorage_bucket.pub")] == "FAIL_STATIC"
    assert "oci" in rep["coverage"]["providers"]
    assert all(f["source"]["line_start"] > 1 for f in rep["findings"] if f["evidence_state"] == "FAIL_STATIC")
