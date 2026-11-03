
resource "google_compute_firewall" "open" {
  name    = "allow-all"
  network = "default"
  direction = "INGRESS"
  priority = 1000
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "all"
  }
}

resource "google_storage_bucket_iam_member" "public" {
  bucket = "acme-data"
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
