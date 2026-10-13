# Sample Terraform for the ShieldIQ IaC scanner (intentionally insecure)
provider "aws" {
  region = "ap-south-1"
}

resource "aws_s3_bucket" "invoices" {
  bucket = "acme-invoices-2026"
}

resource "aws_s3_bucket_public_access_block" "invoices" {
  bucket                  = aws_s3_bucket.invoices.id
  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_security_group" "ssh" {
  name = "allow-ssh-anywhere"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "jump" {
  ami                    = "ami-0abcdef1234567890"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.ssh.id]
  iam_instance_profile   = "jump-admin"
  metadata_options {
    http_tokens = "optional"
  }
  root_block_device {
    encrypted = false
  }
}

resource "aws_db_instance" "orders" {
  identifier              = "orders-db"
  engine                  = "postgres"
  instance_class          = "db.t3.micro"
  publicly_accessible     = true
  storage_encrypted       = false
  backup_retention_period = 1
}

resource "aws_kms_key" "app" {
  description         = "app key"
  enable_key_rotation = false
}
