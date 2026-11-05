package main

import rego.v1

# Evaluated against `terraform show -json` planned_values, so every repo in the
# configuration is checked on every plan, including repos that are not changing.
# Thresholds live in data.json.

repos contains r if {
	some r in input.planned_values.root_module.resources
	r.type == "github_repository"
}

alerts contains r if {
	some r in input.planned_values.root_module.resources
	r.type == "github_repository_vulnerability_alerts"
}

rulesets contains r if {
	some r in input.planned_values.root_module.resources
	r.type == "github_repository_ruleset"
}

deny contains msg if {
	some r in repos
	not regex.match(data.name_pattern, r.values.name)
	msg := sprintf("%s: name must match %s", [r.address, data.name_pattern])
}

deny contains msg if {
	some r in repos
	not r.values.visibility in data.allowed_visibility
	msg := sprintf("%s: visibility '%s' not allowed (allowed: %v)", [r.address, r.values.visibility, data.allowed_visibility])
}

deny contains msg if {
	some r in repos
	not r.values.delete_branch_on_merge == true
	msg := sprintf("%s: delete_branch_on_merge must be true", [r.address])
}

deny contains msg if {
	some a in alerts
	not a.values.enabled == true
	msg := sprintf("%s: vulnerability alerts must be enabled", [a.address])
}

deny contains msg if {
	some r in repos
	some saa in r.values.security_and_analysis
	not secret_scanning_enabled(saa)
	msg := sprintf("%s: secret_scanning must be enabled", [r.address])
}

deny contains msg if {
	some r in repos
	some saa in r.values.security_and_analysis
	not push_protection_enabled(saa)
	msg := sprintf("%s: secret_scanning_push_protection must be enabled", [r.address])
}

deny contains msg if {
	some rs in rulesets
	some rule in rs.values.rules
	not rule.deletion == true
	msg := sprintf("%s: ruleset must block branch deletion", [rs.address])
}

deny contains msg if {
	some rs in rulesets
	some rule in rs.values.rules
	not rule.non_fast_forward == true
	msg := sprintf("%s: ruleset must block force-push", [rs.address])
}

deny contains msg if {
	some rs in rulesets
	some rule in rs.values.rules
	some pr in rule.pull_request
	pr.required_approving_review_count < data.min_required_reviews
	msg := sprintf("%s: requires at least %d approving review(s)", [rs.address, data.min_required_reviews])
}

deny contains msg if {
	some rs in rulesets
	count(object.get(rs.values, "rules", [])) == 0
	msg := sprintf("%s: ruleset has no rules", [rs.address])
}

secret_scanning_enabled(saa) if {
	some ss in saa.secret_scanning
	ss.status == "enabled"
}

push_protection_enabled(saa) if {
	some pp in saa.secret_scanning_push_protection
	pp.status == "enabled"
}
