provider "github" {
  # Auth and owner come from env, set in the workflow:
  #   GITHUB_OWNER, GITHUB_APP_ID, GITHUB_APP_INSTALLATION_ID, GITHUB_APP_PEM_FILE
}

locals {
  repo_files = fileset("${path.module}/../repos", "*.yaml")

  repositories = {
    for f in local.repo_files :
    trimsuffix(f, ".yaml") => merge(
      {
        visibility       = "private"
        topics           = []
        default_branch   = "main"
        required_reviews = 1
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
  delete_branch_on_merge = true
  vulnerability_alerts   = true

  security_and_analysis {
    secret_scanning {
      status = "enabled"
    }
    secret_scanning_push_protection {
      status = "enabled"
    }
  }
}

resource "github_repository_dependabot_security_updates" "this" {
  for_each = local.repositories

  repository = github_repository.this[each.key].name
  enabled    = true
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
    deletion                = true
    non_fast_forward        = true
    required_linear_history = true

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
