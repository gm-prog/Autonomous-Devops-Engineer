# Zero-cloud E2E deployment fixture: built-in constructs only.
terraform {
  required_version = ">= 1.4.0"
}

resource "terraform_data" "e2e_marker" {
  input = "ares-e2e-fixture"
}

output "marker" {
  value = terraform_data.e2e_marker.output
}
