
resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = var.encryption_enabled
}
