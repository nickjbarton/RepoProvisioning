package main

import rego.v1

# Rule logic only. Settings live in policy/guardrails.yaml, loaded as `data`.
# A rule named after an enforce_* key runs only when that key is true.
# Evaluated against planned_values, so every repo in the configuration is checked on every plan.

repos contains r if {
	some r in input.planned_values.root_module.resources
	r.type == "github_repository"
}

alerts contains r if {
	some r in input.planned_values.root_module.resources
	r.type == "github_repository_vulnerability_alerts"
}

dependabot contains r if {
	some r in input.planned_values.root_module.resources
	r.type == "github_repository_dependabot_security_updates"
}

rulesets contains r if {
	some r in input.planned_values.root_module.resources
	r.type == "github_repository_ruleset"
}

# Config check: a missing key would otherwise silently turn a rule off.
deny contains msg if {
	not data.name_pattern
	msg := "guardrails.yaml: 'name_pattern' is missing or has the wrong type"
}

deny contains msg if {
	not data.allowed_visibility
	msg := "guardrails.yaml: 'allowed_visibility' is missing or has the wrong type"
}

deny contains msg if {
	not data.default_visibility
	msg := "guardrails.yaml: 'default_visibility' is missing or has the wrong type"
}

deny contains msg if {
	not is_number(data.min_required_reviews)
	msg := "guardrails.yaml: 'min_required_reviews' is missing or has the wrong type"
}

deny contains msg if {
	not is_number(data.default_required_reviews)
	msg := "guardrails.yaml: 'default_required_reviews' is missing or has the wrong type"
}

deny contains msg if {
	not is_boolean(data.enforce_delete_branch_on_merge)
	msg := "guardrails.yaml: 'enforce_delete_branch_on_merge' is missing or has the wrong type"
}

deny contains msg if {
	not is_boolean(data.enforce_vulnerability_alerts)
	msg := "guardrails.yaml: 'enforce_vulnerability_alerts' is missing or has the wrong type"
}

deny contains msg if {
	not is_boolean(data.enforce_dependabot_security_updates)
	msg := "guardrails.yaml: 'enforce_dependabot_security_updates' is missing or has the wrong type"
}

deny contains msg if {
	not is_boolean(data.enforce_secret_scanning)
	msg := "guardrails.yaml: 'enforce_secret_scanning' is missing or has the wrong type"
}

deny contains msg if {
	not is_boolean(data.enforce_push_protection)
	msg := "guardrails.yaml: 'enforce_push_protection' is missing or has the wrong type"
}

deny contains msg if {
	not is_boolean(data.enforce_ruleset_block_deletion)
	msg := "guardrails.yaml: 'enforce_ruleset_block_deletion' is missing or has the wrong type"
}

deny contains msg if {
	not is_boolean(data.enforce_ruleset_block_force_push)
	msg := "guardrails.yaml: 'enforce_ruleset_block_force_push' is missing or has the wrong type"
}

deny contains msg if {
	not is_boolean(data.enforce_ruleset_linear_history)
	msg := "guardrails.yaml: 'enforce_ruleset_linear_history' is missing or has the wrong type"
}

deny contains msg if {
	some r in repos
	not regex.match(data.name_pattern, r.values.name)
	msg := sprintf("%s: name must match name_pattern (%s)", [r.address, data.name_pattern])
}

deny contains msg if {
	some r in repos
	not r.values.visibility in data.allowed_visibility
	msg := sprintf("%s: visibility '%s' not in allowed_visibility %v", [r.address, r.values.visibility, data.allowed_visibility])
}

deny contains msg if {
	data.enforce_delete_branch_on_merge
	some r in repos
	not r.values.delete_branch_on_merge == true
	msg := sprintf("%s: delete_branch_on_merge must be true (enforce_delete_branch_on_merge)", [r.address])
}

deny contains msg if {
	data.enforce_secret_scanning
	some r in repos
	some saa in r.values.security_and_analysis
	not secret_scanning_enabled(saa)
	msg := sprintf("%s: secret scanning must be enabled (enforce_secret_scanning)", [r.address])
}

deny contains msg if {
	data.enforce_push_protection
	some r in repos
	some saa in r.values.security_and_analysis
	not push_protection_enabled(saa)
	msg := sprintf("%s: push protection must be enabled (enforce_push_protection)", [r.address])
}

deny contains msg if {
	data.enforce_vulnerability_alerts
	some a in alerts
	not a.values.enabled == true
	msg := sprintf("%s: vulnerability alerts must be enabled (enforce_vulnerability_alerts)", [a.address])
}

deny contains msg if {
	data.enforce_dependabot_security_updates
	some d in dependabot
	not d.values.enabled == true
	msg := sprintf("%s: Dependabot security updates must be enabled (enforce_dependabot_security_updates)", [d.address])
}

deny contains msg if {
	data.enforce_ruleset_block_deletion
	some rs in rulesets
	some rule in rs.values.rules
	not rule.deletion == true
	msg := sprintf("%s: ruleset must block branch deletion (enforce_ruleset_block_deletion)", [rs.address])
}

deny contains msg if {
	data.enforce_ruleset_block_force_push
	some rs in rulesets
	some rule in rs.values.rules
	not rule.non_fast_forward == true
	msg := sprintf("%s: ruleset must block force-push (enforce_ruleset_block_force_push)", [rs.address])
}

deny contains msg if {
	data.enforce_ruleset_linear_history
	some rs in rulesets
	some rule in rs.values.rules
	not rule.required_linear_history == true
	msg := sprintf("%s: ruleset must require linear history (enforce_ruleset_linear_history)", [rs.address])
}

deny contains msg if {
	some rs in rulesets
	some rule in rs.values.rules
	some pr in rule.pull_request
	pr.required_approving_review_count < data.min_required_reviews
	msg := sprintf("%s: requires at least %d approving review(s) (min_required_reviews)", [rs.address, data.min_required_reviews])
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
