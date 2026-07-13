variable "project" {
  description = "Project identifier shared across bootstrap, relay, and observer infrastructure."
  type        = string
  default     = "quicnet"
}

variable "environment" {
  description = "Environment slug for infrastructure naming."
  type        = string
  default     = "dev"
}

variable "regions" {
  description = "Initial regional topology for milestone-one test infrastructure."
  type        = list(string)
  default     = ["us-east-1", "eu-central-1", "us-west-2"]
}

variable "node_roles" {
  description = "Logical fleet roles tracked by the current workspace deploy targets."
  type        = set(string)
  default     = ["bootstrap", "relay"]
}
