terraform {
  required_version = ">= 1.2.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# --- VPC NETWORK INFRASTRUCTURE (VIRTUAL PRIVATE CLOUD) ---
resource "aws_vpc" "devops_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "devops-production-vpc"
    Environment = "production"
    Orchestrated= "DevOps.AI Agent Swarm"
  }
}

# --- SUBNET CONSTRAINTS ---
resource "aws_subnet" "public_subnet_a" {
  vpc_id            = aws_vpc.devops_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = { Name = "devops-public-a" }
}

resource "aws_subnet" "private_subnet_a" {
  vpc_id            = aws_vpc.devops_vpc.id
  cidr_block        = "10.0.10.0/24"
  availability_zone = "${var.aws_region}a"

  tags = { Name = "devops-private-a" }
}

# --- CONTAINER SUITE REPOSITORY (ECR) ---
resource "aws_ecr_repository" "app_repo" {
  name                 = "devops-agent-workload"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    PolicyCode = "PCI-DSS-Scanning"
  }
}

# --- AWS ECS FARGATE CLUSTER (SECURE ORCHESTRATION SHIELD) ---
resource "aws_ecs_cluster" "devops_cluster" {
  name = "devops-production-fargate-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}
