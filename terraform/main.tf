provider "github" {
  # Auth and owner come from env, set in the workflow:
  #   GITHUB_OWNER, GITHUB_APP_ID, GITHUB_APP_INSTALLATION_ID, GITHUB_APP_PEM_FILE

  # Space out write calls and retry 403 rate-limit responses (GitHub secondary limits).
  parallel_requests = false
  write_delay_ms    = 3000
  max_retries       = 5
}

locals {
  # Shared with the policy. Edit policy/guardrails.yaml, not this file, to change guardrails.
  guardrails = yamldecode(file("${path.module}/../policy/guardrails.yaml"))

  repo_files = fileset("${path.module}/../repos", "*.yaml")

  repositories = {
    for f in local.repo_files :
    trimsuffix(f, ".yaml") => merge(
      {
        visibility       = local.guardrails.default_visibility
        topics           = []
        default_branch   = "main"
        required_reviews = local.guardrails.default_required_reviews
      },
      yamldecode(file("${path.module}/../repos/${f}"))
    )
  }
}

resource "github_repository" "this" {
  for_each = local.repositories

  name                   = each.key
  description            = each.value.description
  visibility             = each.value.visibility
  topics                 = each.value.topics
  auto_init              = true
  has_issues             = true
  delete_branch_on_merge = local.guardrails.enforce_delete_branch_on_merge

  security_and_analysis {
    secret_scanning {
      status = local.guardrails.enforce_secret_scanning ? "enabled" : "disabled"
    }
    secret_scanning_push_protection {
      status = local.guardrails.enforce_push_protection ? "enabled" : "disabled"
    }
  }
}

resource "github_repository_vulnerability_alerts" "this" {
  for_each = local.repositories

  repository = github_repository.this[each.key].name
  enabled    = local.guardrails.enforce_vulnerability_alerts
}

resource "github_repository_dependabot_security_updates" "this" {
  for_each = local.repositories

  repository = github_repository.this[each.key].name
  enabled    = local.guardrails.enforce_dependabot_security_updates
}

resource "github_repository_ruleset" "default_branch" {
  for_each = local.repositories

  # CODEOWNERS must land before the ruleset blocks direct pushes to the default branch.
  depends_on = [github_repository_file.codeowners]

  name        = "default-branch-protection"
  repository  = github_repository.this[each.key].name
  target      = "branch"
  enforcement = "active"

  conditions {
    ref_name {
      include = ["~DEFAULT_BRANCH"]
      exclude = []
    }
  }

  rules {
    deletion                = local.guardrails.enforce_ruleset_block_deletion
    non_fast_forward        = local.guardrails.enforce_ruleset_block_force_push
    required_linear_history = local.guardrails.enforce_ruleset_linear_history

    pull_request {
      required_approving_review_count   = each.value.required_reviews
      dismiss_stale_reviews_on_push     = true
      require_code_owner_review         = true
      require_last_push_approval        = true
      required_review_thread_resolution = true
    }
  }
}

resource "github_repository_file" "codeowners" {
  for_each = local.repositories

  repository          = github_repository.this[each.key].name
  branch              = github_repository.this[each.key].default_branch
  file                = ".github/CODEOWNERS"
  content             = "* ${each.value.codeowners}\n"
  commit_message      = "Add CODEOWNERS (managed by Terraform)"
  commit_author       = "repo-provisioning"
  commit_email        = "repo-provisioning@users.noreply.github.com"
  overwrite_on_create = true
}
