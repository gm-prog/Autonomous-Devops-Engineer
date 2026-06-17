variable "aws_region" {
  description = "Target deployment region mapping to AWS Cloud locations"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "The VPC base subnet CIDR block definition"
  type        = string
  default     = "10.0.0.0/16"
}
