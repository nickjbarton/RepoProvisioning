variable "github_owner" {
  description = "GitHub user or org that owns the repositories. Also exported as GITHUB_OWNER in the workflow."
  type        = string
  default     = null
}
