# One-time: drop njb2-test-repo from state without calling GitHub.
# The repo was deleted by hand. Its Dependabot read returns 404 and blocks every plan.
# Safe to delete this file once the apply has run and the plan shows no njb2 changes.

removed {
  from = github_repository_dependabot_security_updates.this["njb2-test-repo"]

  lifecycle {
    destroy = false
  }
}

removed {
  from = github_repository.this["njb2-test-repo"]

  lifecycle {
    destroy = false
  }
}
