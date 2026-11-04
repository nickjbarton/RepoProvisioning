package main

import rego.v1

compliant_repo := {
	"address": "github_repository.this[\"demo-app\"]",
	"type": "github_repository",
	"change": {
		"actions": ["create"],
		"after": {
			"name": "demo-app",
			"visibility": "private",
			"delete_branch_on_merge": true,
			"vulnerability_alerts": true,
			"security_and_analysis": [{
				"secret_scanning": [{"status": "enabled"}],
				"secret_scanning_push_protection": [{"status": "enabled"}],
			}],
		},
	},
}

compliant_ruleset := {
	"address": "github_repository_ruleset.default_branch[\"demo-app\"]",
	"type": "github_repository_ruleset",
	"change": {
		"actions": ["create"],
		"after": {"rules": [{
			"deletion": true,
			"non_fast_forward": true,
			"pull_request": [{"required_approving_review_count": 1}],
		}]},
	},
}

test_compliant_plan_passes if {
	count(deny) == 0 with input as {"resource_changes": [compliant_repo, compliant_ruleset]}
}

test_bad_name_denied if {
	bad := object.union(compliant_repo, {"change": {"actions": ["create"], "after": object.union(compliant_repo.change.after, {"name": "Bad_Name"})}})
	count(deny) == 1 with input as {"resource_changes": [bad]}
}

test_public_denied_when_not_allowed if {
	bad := object.union(compliant_repo, {"change": {"actions": ["create"], "after": object.union(compliant_repo.change.after, {"visibility": "internal"})}})
	count(deny) == 1 with input as {"resource_changes": [bad]}
}

test_secret_scanning_disabled_denied if {
	after := object.union(compliant_repo.change.after, {"security_and_analysis": [{
		"secret_scanning": [{"status": "disabled"}],
		"secret_scanning_push_protection": [{"status": "enabled"}],
	}]})
	bad := object.union(compliant_repo, {"change": {"actions": ["create"], "after": after}})
	count(deny) == 1 with input as {"resource_changes": [bad]}
}

test_ruleset_without_deletion_block_denied if {
	bad := object.union(compliant_ruleset, {"change": {"actions": ["create"], "after": {"rules": [{
		"deletion": false,
		"non_fast_forward": true,
		"pull_request": [{"required_approving_review_count": 1}],
	}]}}})
	count(deny) == 1 with input as {"resource_changes": [bad]}
}

test_ruleset_zero_reviews_denied if {
	bad := object.union(compliant_ruleset, {"change": {"actions": ["create"], "after": {"rules": [{
		"deletion": true,
		"non_fast_forward": true,
		"pull_request": [{"required_approving_review_count": 0}],
	}]}}})
	count(deny) == 1 with input as {"resource_changes": [bad]}
}
