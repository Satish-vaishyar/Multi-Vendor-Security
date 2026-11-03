
provider "aws" {
  region = "us-east-1"
}

# SSH open to the whole internet
resource "aws_security_group" "web" {
  name = "web-sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Public bucket: every public-access block turned off
resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = "acme-logs"
  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}

# Bucket policy granting everyone
resource "aws_s3_bucket_policy" "logs" {
  bucket = "acme-logs"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::acme-logs/*"
    }]
  })
}

# Wildcard admin policy
resource "aws_iam_policy" "admin" {
  name = "admin-all"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# Role trusting anyone
resource "aws_iam_role" "ec2" {
  name = "ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Unencrypted volume
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}

# Public, unencrypted database
resource "aws_db_instance" "main" {
  identifier          = "maindb"
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
}

# IMDSv1 explicitly enabled
resource "aws_instance" "web" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }
}

# CloudTrail without multi-region and without log validation
resource "aws_cloudtrail" "audit" {
  name                       = "audit"
  s3_bucket_name             = "acme-logs"
  enable_log_file_validation = false
  is_multi_region_trail      = false
}
