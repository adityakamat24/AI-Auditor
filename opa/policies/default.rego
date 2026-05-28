package auditor.gate

# Default inline-gate policy (PRD §9.4.1). Input = a normalized event; output = data.auditor.gate.decision
# = {"decision": "ALLOW"|"DENY"|"CONFIRM", "reasons": [...]}. Precedence: DENY > CONFIRM > ALLOW.
import rego.v1

# Sensitive path fragments (Linux + Windows). Matched case-insensitively as substrings.
sensitive_paths := [
	"/etc/", "/proc/", "/sys/", "/root/.ssh/", "/.ssh/", ".ssh/",
	".aws/credentials", "/proc/self/environ", "id_rsa",
]

# Egress destinations the agent may reach; anything else is denied.
allowlisted_dest_substrings := ["127.0.0.1", "localhost", "api.anthropic.com"]

is_sensitive_path(p) if {
	some frag in sensitive_paths
	contains(lower(p), lower(frag))
}

is_allowlisted_dest(d) if {
	some allowed in allowlisted_dest_substrings
	contains(lower(d), lower(allowed))
}

# ---- violation reason sets ----

deny_reasons contains msg if {
	input.event_type == "syscall.openat"
	is_sensitive_path(input.path)
	msg := sprintf("sensitive path access: %v", [input.path])
}

deny_reasons contains msg if {
	input.event_type == "tool_call.start"
	input.tool_name == "exec_shell"
	not has_declared_purpose
	msg := "exec_shell requires a declared_purpose"
}

# True only when declared_purpose is present, non-null, and non-empty (handles missing/null/"" alike).
has_declared_purpose if {
	input.declared_purpose != null
	input.declared_purpose != ""
}

deny_reasons contains msg if {
	input.event_type == "syscall.connect"
	input.dest
	not is_allowlisted_dest(input.dest)
	msg := sprintf("egress to non-allowlisted destination: %v", [input.dest])
}

confirm_reasons contains msg if {
	input.event_type == "tool_call.start"
	input.tool_name == "send_email"
	contains(lower(object.get(input.tool_args, "body", "")), "confidential")
	msg := "outbound email contains 'confidential'"
}

# ---- final decision (mutually-exclusive guards avoid complete-rule conflicts) ----

decision := {"decision": "DENY", "reasons": rs} if {
	count(deny_reasons) > 0
	rs := [m | some m in deny_reasons]
}

decision := {"decision": "CONFIRM", "reasons": rs} if {
	count(deny_reasons) == 0
	count(confirm_reasons) > 0
	rs := [m | some m in confirm_reasons]
}

decision := {"decision": "ALLOW", "reasons": []} if {
	count(deny_reasons) == 0
	count(confirm_reasons) == 0
}
