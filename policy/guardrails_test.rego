package main

import rego.v1

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

compliant_ruleset := {
	"address": "github_repository_ruleset.default_branch[\"demo-app\"]",
	"type": "github_repository_ruleset",
	"values": {"rules": [{
		"deletion": true,
		"non_fast_forward": true,
		"pull_request": [{"required_approving_review_count": 1}],
	}]},
}

with_values(resource, changes) := object.union(resource, {"values": object.union(resource.values, changes)})

test_compliant_plan_passes if {
	count(deny) == 0 with input as plan([compliant_repo, compliant_alerts, compliant_ruleset])
}

test_bad_name_denied if {
	bad := with_values(compliant_repo, {"name": "Bad_Name"})
	count(deny) == 1 with input as plan([bad])
}

test_internal_visibility_denied if {
	bad := with_values(compliant_repo, {"visibility": "internal"})
	count(deny) == 1 with input as plan([bad])
}

test_secret_scanning_disabled_denied if {
	bad := with_values(compliant_repo, {"security_and_analysis": [{
		"secret_scanning": [{"status": "disabled"}],
		"secret_scanning_push_protection": [{"status": "enabled"}],
	}]})
	count(deny) == 1 with input as plan([bad])
}

test_alerts_disabled_denied if {
	bad := with_values(compliant_alerts, {"enabled": false})
	count(deny) == 1 with input as plan([bad])
}

test_ruleset_without_deletion_block_denied if {
	bad := with_values(compliant_ruleset, {"rules": [{
		"deletion": false,
		"non_fast_forward": true,
		"pull_request": [{"required_approving_review_count": 1}],
	}]})
	count(deny) == 1 with input as plan([bad])
}

test_ruleset_zero_reviews_denied if {
	bad := with_values(compliant_ruleset, {"rules": [{
		"deletion": true,
		"non_fast_forward": true,
		"pull_request": [{"required_approving_review_count": 0}],
	}]})
	count(deny) == 1 with input as plan([bad]) with data.min_required_reviews as 1
}

test_unchanged_repo_is_checked if {
	# No "actions" field: planned_values includes repos that are not changing.
	bad := with_values(compliant_repo, {"visibility": "internal"})
	count(deny) == 1 with input as plan([bad])
}
