# RepoProvisioning

Provisions GitHub repositories with Terraform and enforces compliance guardrails before any change applies.

## How it works

1. Add `repos/<repo-name>.yaml` (see `repos/example-repo.yaml.example`) and open a PR.
2. `terraform-plan.yml` runs fmt, validate, policy unit tests, plan, then Conftest against the plan JSON. Failing policy blocks the PR.
3. Merge to `main`. `terraform-apply.yml` re-runs plan and the policy gate, then pauses at the `repo-provisioning-prod` environment for approval, then applies the saved plan.

Each repo gets :

| Resource | Setting |
|---|---|
| `github_repository` | Private by default, delete branch on merge, Dependabot alerts, secret scanning and push protection on |
| `github_repository_dependabot_security_updates` | Enabled |
| `github_repository_ruleset` | Default branch: no deletion, no force-push, linear history, PR required, approvals required, code-owner review, stale reviews dismissed |
| `github_repository_file` | `.github/CODEOWNERS` with `* <codeowners>` |

## Guardrails (`policy/`)

| Rule | Denies |
|---|---|
| Name pattern | Names not matching `^[a-z][a-z0-9-]{2,49}$` |
| Visibility | Values not in `allowed_visibility` (default `public`, `private`) |
| Security | Secret scanning or push protection disabled, Dependabot alerts off, branch deletion on merge off |
| Ruleset | Missing deletion or force-push block, fewer than `min_required_reviews` approvals |

Thresholds live in `policy/data.json`. Logic lives in `policy/guardrails.rego`. Unit tests are in `policy/guardrails_test.rego` (`conftest verify`).

Tighten `allowed_visibility` to `["private"]` once the account has GitHub Pro or Team.

## Setup (one time)

**Terraform Cloud**
- Create organisation and workspace `repo-provisioning`.
- Set workspace **Execution Mode** to **Local**. Plans and applies then run on the Actions runner with its GitHub credentials. State stays in TF Cloud.
- Create a team API token.

**GitHub App** (owned by the account that will hold the repos)
- Permissions: Administration (read and write), Contents (read and write), Metadata (read), Dependabot alerts (read and write).
- Install on the target account for all repositories or selected repositories.
- Generate a private key (`.pem`).

**GitHub repo settings for `nickjbarton/RepoProvisioning`**

| Type | Name | Value |
|---|---|---|
| Variable | `TF_CLOUD_ORGANIZATION` | Your TF Cloud org |
| Variable | `REPO_OWNER` | Owner of the target repos |
| Variable | `APP_ID` | App ID |
| Variable | `APP_INSTALLATION_ID` | Installation ID |
| Secret | `TF_API_TOKEN` | TF Cloud token |
| Secret | `APP_PRIVATE_KEY` | Full contents of the `.pem` file |

Create environment `repo-provisioning-prod` with required reviewers.

## Limits on a Free personal account

- Rulesets and branch protection do not apply to **private** repos on Free. Use public repos for testing, or upgrade.
- Secret scanning push protection on **private** repos requires GitHub Advanced Security. Public repos are covered.
- Dependabot security updates and vulnerability alerts apply on Free for both public and private repos.

## Test plan

1. Open a PR adding `repos/guardrail-test-public.yaml` with `visibility: public`. Confirm plan and policy pass.
2. Open a PR with an uppercase name or `visibility: internal`. Confirm the policy gate fails.
3. Merge test 1, approve the environment, then confirm in the GitHub UI: ruleset active, CODEOWNERS present, secret scanning enabled.
4. Remove the test file in a PR, merge, approve. Confirm the repo is destroyed.

## Local checks

```bash
cd terraform && terraform fmt -check -recursive && terraform init -backend=false && terraform validate
cd .. && conftest verify --policy policy --data policy/data.json
```
