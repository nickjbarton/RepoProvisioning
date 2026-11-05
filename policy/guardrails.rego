package main

import rego.v1

# Evaluated against `terraform show -json` output. Thresholds live in data.json.

repo_creates contains rc if {
	some rc in input.resource_changes
	rc.type == "github_repository"
	"create" in rc.change.actions
}

alert_creates contains rc if {
	some rc in input.resource_changes
	rc.type == "github_repository_vulnerability_alerts"
	"create" in rc.change.actions
}

ruleset_creates contains rc if {
	some rc in input.resource_changes
	rc.type == "github_repository_ruleset"
	"create" in rc.change.actions
}

deny contains msg if {
	some rc in repo_creates
	name := rc.change.after.name
	not regex.match(data.name_pattern, name)
	msg := sprintf("%s: name must match %s", [rc.address, data.name_pattern])
}

deny contains msg if {
	some rc in repo_creates
	not rc.change.after.visibility in data.allowed_visibility
	msg := sprintf("%s: visibility '%s' not allowed (allowed: %v)", [rc.address, rc.change.after.visibility, data.allowed_visibility])
}

deny contains msg if {
	some rc in repo_creates
	not rc.change.after.delete_branch_on_merge == true
	msg := sprintf("%s: delete_branch_on_merge must be true", [rc.address])
}

deny contains msg if {
	some rc in alert_creates
	not rc.change.after.enabled == true
	msg := sprintf("%s: vulnerability alerts must be enabled", [rc.address])
}

deny contains msg if {
	some rc in repo_creates
	some saa in rc.change.after.security_and_analysis
	not secret_scanning_enabled(saa)
	msg := sprintf("%s: secret_scanning must be enabled", [rc.address])
}

deny contains msg if {
	some rc in repo_creates
	some saa in rc.change.after.security_and_analysis
	not push_protection_enabled(saa)
	msg := sprintf("%s: secret_scanning_push_protection must be enabled", [rc.address])
}

deny contains msg if {
	some rc in ruleset_creates
	some r in rc.change.after.rules
	not r.deletion == true
	msg := sprintf("%s: ruleset must block branch deletion", [rc.address])
}

deny contains msg if {
	some rc in ruleset_creates
	some r in rc.change.after.rules
	not r.non_fast_forward == true
	msg := sprintf("%s: ruleset must block force-push", [rc.address])
}

deny contains msg if {
	some rc in ruleset_creates
	some r in rc.change.after.rules
	some pr in r.pull_request
	pr.required_approving_review_count < data.min_required_reviews
	msg := sprintf("%s: requires at least %d approving review(s)", [rc.address, data.min_required_reviews])
}

deny contains msg if {
	some rc in ruleset_creates
	count(rc.change.after.rules) == 0
	msg := sprintf("%s: ruleset has no rules", [rc.address])
}

secret_scanning_enabled(saa) if {
	some ss in saa.secret_scanning
	ss.status == "enabled"
}

push_protection_enabled(saa) if {
	some pp in saa.secret_scanning_push_protection
	pp.status == "enabled"
}
