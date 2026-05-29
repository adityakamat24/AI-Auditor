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

# Destructive file_write: empty content is the common "delete the file" path when the agent
# only has a write tool. CONFIRM (not DENY) so a reviewer approves explicitly - some legitimate
# runs truncate intentionally, but the asymmetry (rare and reversible-via-review vs silent data
# loss) makes CONFIRM the right default. The user-facing intent is also flagged separately by
# ASI01's destructive-intent patterns on the declared goal.
confirm_reasons contains msg if {
	input.event_type == "tool_call.start"
	input.tool_name == "file_write"
	object.get(input.tool_args, "content", "") == ""
	msg := sprintf(
		"file_write with empty content on %v - reviewer approval required for truncation/deletion",
		[object.get(input.tool_args, "path", "(unknown path)")],
	)
}

# Destructive shell commands embedded in exec_shell args. exec_shell is already DENY without
# declared_purpose; this rule is the second-line check for the with-purpose case (a declared
# purpose doesn't make `rm -rf /` safe). CONFIRM so a reviewer signs off, not DENY outright -
# legitimate ops scripts sometimes need destructive ops.
destructive_shell_patterns := [
	"rm -rf", "rm -r", "rm -f", "rmdir",
	"del /", "rd /", "format ", "format/",
	"drop table", "drop database", "drop schema",
	"truncate table", "delete from",
	"wipe ", "shred ", "mkfs",
	":(){:|:&};:",  # fork bomb
]

confirm_reasons contains msg if {
	input.event_type == "tool_call.start"
	input.tool_name == "exec_shell"
	some pat in destructive_shell_patterns
	contains(lower(object.get(input.tool_args, "command", "")), pat)
	msg := sprintf("exec_shell destructive pattern %q - reviewer approval required", [pat])
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
