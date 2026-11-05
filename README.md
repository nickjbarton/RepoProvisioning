# RepoProvisioning

Provisions GitHub repositories with Terraform and enforces compliance guardrails before any change applies.

## How it works

1. Add `repos/<repo-name>.yaml` (see `repos/example-repo.yaml.example`) and open a PR.
2. `terraform-plan.yml` runs fmt, validate, policy unit tests, a plan, then Conftest against the plan JSON. A failing guardrail blocks the PR.
3. Merge to `main`. `terraform-apply.yml` runs the same plan and policy gate, pauses at the `repo-provisioning-prod` environment for approval, then applies the saved plan.

Each YAML file becomes one set of resources in `terraform/main.tf`, created with `for_each`:

| Resource | Setting |
|---|---|
| `github_repository` | Name, description, visibility, topics. Delete branch on merge on. Secret scanning and push protection on. |
| `github_repository_vulnerability_alerts` | Enabled |
| `github_repository_dependabot_security_updates` | Enabled |
| `github_repository_ruleset` | Default branch: no deletion, no force-push, linear history, PR required, approvals required, code-owner review, stale reviews dismissed |
| `github_repository_file` | `.github/CODEOWNERS` with `* <codeowners>` |

## Repo file format

One file per repo, named `<repo-name>.yaml`. The file name must match the repo name.

| Key | Required | Default | Notes |
|---|---|---|---|
| `description` | Yes | None | Shown on the repo |
| `codeowners` | Yes | None | Written as the `*` owner in CODEOWNERS, for example `@org/team` |
| `visibility` | No | `private` | Must be in `allowed_visibility` |
| `topics` | No | `[]` | |
| `required_reviews` | No | `1` | Must be at least `min_required_reviews` |

## Guardrails

Guardrails come in two kinds. Which kind a rule is determines where you change it.

**Parameter guardrails** take a value from `policy/data.json`:

| Parameter | Current value | Effect |
|---|---|---|
| `name_pattern` | `^[a-z][a-z0-9-]{2,49}$` | Repo names must match this regex |
| `allowed_visibility` | `["public", "private"]` | Visibility must be one of these values |
| `min_required_reviews` | `1` | Rulesets must require at least this many approvals |

**Fixed guardrails** are hardcoded in `policy/guardrails.rego`. Changing them is a code change:

| Rule | Denies |
|---|---|
| Branch deletion on merge | `delete_branch_on_merge` is not `true` |
| Vulnerability alerts | `github_repository_vulnerability_alerts` is not enabled |
| Secret scanning | Secret scanning is not `enabled` |
| Push protection | Secret scanning push protection is not `enabled` |
| Ruleset deletion block | The ruleset does not block branch deletion |
| Ruleset force-push block | The ruleset does not block force-push |
| Ruleset rules present | The ruleset has no rules |

### Files

| File | Purpose |
|---|---|
| `policy/data.json` | Parameter values |
| `policy/guardrails.rego` | Rule logic. Each `deny` block produces one failure message. |
| `policy/guardrails_test.rego` | Unit tests. Each test passes a fake plan to the rules. |
| `terraform/main.tf` | The resource settings the rules check. A rule can only check what Terraform sets. |

### What is checked

The policy checks the **planned state of every repo** in `repos/`, including repos that are not changing. Each plan re-evaluates all of them against the current `data.json` and rules. Changing a threshold therefore fails the plan for any existing repo that no longer complies. Fix the repo, or revert the threshold, before merging.

## Changing a parameter

Example: raise `min_required_reviews` from 1 to 2.

1. Edit `policy/data.json`.
2. Run the local checks below. If an existing test depends on the old value, update the test.
3. Open a PR. The plan workflow runs the policy against the new value.

The change applies to every repo in `repos/` on the next plan. A repo whose ruleset requires fewer approvals than the new minimum fails the plan, and so does any per-repo `required_reviews` below the minimum.

## Adding a new guardrail

### Option A: a new parameter

Use this when the rule needs a value someone may want to change.

1. Add the value to `policy/data.json`:

   ```json
   {
     "name_pattern": "^[a-z][a-z0-9-]{2,49}$",
     "allowed_visibility": ["public", "private"],
     "min_required_reviews": 1,
     "max_description_length": 200
   }
   ```

2. Add a rule to `policy/guardrails.rego` that reads it with `data.<name>`:

   ```rego
   deny contains msg if {
   	some r in repos
   	count(r.values.description) > data.max_description_length
   	msg := sprintf("%s: description must be at most %d characters", [r.address, data.max_description_length])
   }
   ```

3. Add a passing test and a failing test to `policy/guardrails_test.rego`.

### Option B: a new Terraform setting

Use this when the rule checks an attribute of a resource.

1. Set the attribute in `terraform/main.tf`. If it is a new resource type, add it with `for_each = local.repositories`.
2. Add a `deny` rule. Use `repos` for `github_repository`, or add a new set like `repos` that selects the resource type from `input.planned_values.root_module.resources`:

   ```rego
   deny contains msg if {
   	some r in repos
   	r.values.has_wiki == true
   	msg := sprintf("%s: wiki must be disabled", [r.address])
   }
   ```

   Note that `not x == true` also denies when the attribute is missing from the plan. Test the value Terraform actually sets.

3. Add a passing test and a failing test to `policy/guardrails_test.rego`. A failing test builds a fake plan entry with the bad value and asserts `count(deny) == 1`.

### Checklist for any new rule

- Rule added to `guardrails.rego` or a parameter added to `data.json`
- Terraform sets the attribute the rule checks
- Passing and failing tests added
- `conftest verify` passes locally
- PR opened and the plan workflow shows the rule running

## Setup (one time)

**Terraform Cloud**
- Create organisation and workspace `repo-provisioning`.
- Set workspace **Execution Mode** to **Local**. Plans and applies then run on the Actions runner with its GitHub credentials. State stays in TF Cloud.
- Create a team API token.

**GitHub App** (owned by the account or organisation that will hold the repos)
- Permissions: Administration (read and write), Contents (read and write), Metadata (read), Dependabot alerts (read and write).
- Install on the target account for all repositories or selected repositories.
- Generate a private key (`.pem`).

**GitHub repo settings for this repository**

| Type | Name | Value |
|---|---|---|
| Variable | `TF_CLOUD_ORGANIZATION` | Your TF Cloud org |
| Variable | `REPO_OWNER` | Owner of the target repos |
| Variable | `APP_ID` | App ID |
| Variable | `APP_INSTALLATION_ID` | Installation ID |
| Secret | `TF_API_TOKEN` | TF Cloud token |
| Secret | `APP_PRIVATE_KEY` | Full contents of the `.pem` file |

Create environment `repo-provisioning-prod` with required reviewers.

## Limits on a Free personal account or organisation

- Rulesets and branch protection do not apply to **private** repos on Free. Use public repos for testing, or upgrade.
- Secret scanning push protection on **private** repos requires GitHub Advanced Security. Public repos are covered.
- Dependabot security updates and vulnerability alerts apply on Free for both public and private repos.

Tighten `allowed_visibility` to `["private"]` once the account has GitHub Pro, Team or Enterprise.

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

`conftest verify` runs the unit tests. To test a real plan locally, run `terraform show -json tfplan > plan.json` and then `conftest test plan.json --policy policy --data policy/data.json`.

## Known gaps

- The policy checks planned state from Terraform, so it only sees what the provider reads. Settings that the provider does not read, or that Terraform does not manage, are not checked.
- Fixed guardrails are hardcoded. There is no parameter for them.
- The checks rely on the attribute names in the Terraform provider. A provider upgrade can rename an attribute, so the tests should be run after upgrading `integrations/github`.
