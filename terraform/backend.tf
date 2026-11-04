terraform {
  cloud {
    # Organization is set via TF_CLOUD_ORGANIZATION (repo variable).
    workspaces {
      name = "repo-provisioning"
    }
  }
}
