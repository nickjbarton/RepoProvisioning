package main

import rego.v1

# Each test pins the settings it depends on, so the tests do not change when an admin edits guardrails.yaml.

plan(resources) := {"planned_values": {"root_module": {"resources": resources}}}

compliant_repo := {
	"address": "github_repository.this[\"demo-app\"]",
	"type": "github_repository",
	"values": {
		"name": "demo-app",
		"visibility": "private",
		"delete_branch_on_merge": true,
		"security_and_analysis": [{
			"secret_scanning": [{"status": "enabled"}],
			"secret_scanning_push_protection": [{"status": "enabled"}],
		}],
	},
}

compliant_alerts := {
	"address": "github_repository_vulnerability_alerts.this[\"demo-app\"]",
	"type": "github_repository_vulnerability_alerts",
	"values": {"enabled": true},
}

compliant_dependabot := {
	"address": "github_repository_dependabot_security_updates.this[\"demo-app\"]",
	"type": "github_repository_dependabot_security_updates",
	"values": {"enabled": true},
}

compliant_ruleset := {
	"address": "github_repository_ruleset.default_branch[\"demo-app\"]",
	"type": "github_repository_ruleset",
	"values": {"rules": [{
		"deletion": true,
		"non_fast_forward": true,
		"required_linear_history": true,
		"pull_request": [{"required_approving_review_count": 1}],
	}]},
}

with_values(resource, changes) := object.union(resource, {"values": object.union(resource.values, changes)})

test_compliant_plan_passes if {
	count(deny) == 0
		with input as plan([compliant_repo, compliant_alerts, compliant_dependabot, compliant_ruleset])
		with data.enforce_delete_branch_on_merge as true
		with data.enforce_secret_scanning as true
		with data.enforce_push_protection as true
		with data.enforce_vulnerability_alerts as true
		with data.enforce_dependabot_security_updates as true
		with data.enforce_ruleset_block_deletion as true
		with data.enforce_ruleset_block_force_push as true
		with data.enforce_ruleset_linear_history as true
		with data.min_required_reviews as 1
		with data.name_pattern as "^[a-z][a-z0-9-]{2,49}$"
		with data.allowed_visibility as ["public", "private"]
}

test_bad_name_denied if {
	bad := with_values(compliant_repo, {"name": "Bad_Name"})
	count(deny) == 1 with input as plan([bad]) with data.name_pattern as "^[a-z][a-z0-9-]{2,49}$"
}

test_visibility_not_allowed_denied if {
	bad := with_values(compliant_repo, {"visibility": "internal"})
	count(deny) == 1 with input as plan([bad]) with data.allowed_visibility as ["public", "private"]
}

test_visibility_allowed_when_listed if {
	ok := with_values(compliant_repo, {"visibility": "internal"})
	count(deny) == 0 with input as plan([ok]) with data.allowed_visibility as ["public", "private", "internal"]
}

test_unchanged_repo_is_checked if {
	bad := with_values(compliant_repo, {"visibility": "internal"})
	count(deny) == 1 with input as plan([bad]) with data.allowed_visibility as ["public", "private"]
}

test_secret_scanning_disabled_denied if {
	bad := with_values(compliant_repo, {"security_and_analysis": [{
		"secret_scanning": [{"status": "disabled"}],
		"secret_scanning_push_protection": [{"status": "enabled"}],
	}]})
	count(deny) == 1 with input as plan([bad]) with data.enforce_secret_scanning as true
}

test_secret_scanning_rule_off_allows_disabled if {
	bad := with_values(compliant_repo, {"security_and_analysis": [{
		"secret_scanning": [{"status": "disabled"}],
		"secret_scanning_push_protection": [{"status": "enabled"}],
	}]})
	count(deny) == 0 with input as plan([bad]) with data.enforce_secret_scanning as false
}

test_push_protection_disabled_denied if {
	bad := with_values(compliant_repo, {"security_and_analysis": [{
		"secret_scanning": [{"status": "enabled"}],
		"secret_scanning_push_protection": [{"status": "disabled"}],
	}]})
	count(deny) == 1 with input as plan([bad]) with data.enforce_push_protection as true
}

test_delete_branch_on_merge_off_denied if {
	bad := with_values(compliant_repo, {"delete_branch_on_merge": false})
	count(deny) == 1 with input as plan([bad]) with data.enforce_delete_branch_on_merge as true
}

test_alerts_disabled_denied if {
	bad := with_values(compliant_alerts, {"enabled": false})
	count(deny) == 1 with input as plan([bad]) with data.enforce_vulnerability_alerts as true
}

test_dependabot_disabled_denied if {
	bad := with_values(compliant_dependabot, {"enabled": false})
	count(deny) == 1 with input as plan([bad]) with data.enforce_dependabot_security_updates as true
}

test_ruleset_without_deletion_block_denied if {
	bad := with_values(compliant_ruleset, {"rules": [{
		"deletion": false,
		"non_fast_forward": true,
		"required_linear_history": true,
		"pull_request": [{"required_approving_review_count": 1}],
	}]})
	count(deny) == 1 with input as plan([bad]) with data.enforce_ruleset_block_deletion as true
}

test_ruleset_without_force_push_block_denied if {
	bad := with_values(compliant_ruleset, {"rules": [{
		"deletion": true,
		"non_fast_forward": false,
		"required_linear_history": true,
		"pull_request": [{"required_approving_review_count": 1}],
	}]})
	count(deny) == 1 with input as plan([bad]) with data.enforce_ruleset_block_force_push as true
}

test_ruleset_without_linear_history_denied if {
	bad := with_values(compliant_ruleset, {"rules": [{
		"deletion": true,
		"non_fast_forward": true,
		"required_linear_history": false,
		"pull_request": [{"required_approving_review_count": 1}],
	}]})
	count(deny) == 1 with input as plan([bad]) with data.enforce_ruleset_linear_history as true
}

test_ruleset_below_min_reviews_denied if {
	bad := with_values(compliant_ruleset, {"rules": [{
		"deletion": true,
		"non_fast_forward": true,
		"required_linear_history": true,
		"pull_request": [{"required_approving_review_count": 0}],
	}]})
	count(deny) == 1 with input as plan([bad]) with data.min_required_reviews as 1
}

test_ruleset_meets_raised_min_reviews if {
	ok := with_values(compliant_ruleset, {"rules": [{
		"deletion": true,
		"non_fast_forward": true,
		"required_linear_history": true,
		"pull_request": [{"required_approving_review_count": 2}],
	}]})
	count(deny) == 0 with input as plan([ok]) with data.min_required_reviews as 2
}

test_missing_setting_denied if {
	count(deny) == 1 with input as plan([]) with data.enforce_push_protection as null
}
