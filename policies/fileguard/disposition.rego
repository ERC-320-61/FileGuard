package fileguard.disposition

# Stable conclusion vocabulary for FileGuard disposition policies.
supported_conclusions := {"CLEAN", "SUSPICIOUS", "MALICIOUS", "INCOMPLETE"}

# Single deterministic decision rule, evaluated top to bottom via `else`.
# Precedence: MALICIOUS > INCOMPLETE > SUSPICIOUS > CLEAN > fail-closed
# default INCOMPLETE. Only the first matching branch applies.
#
# A completed ClamAV detection is MALICIOUS even when other analysis in the
# same evidence document is incomplete: the destination is quarantine either
# way, but MALICIOUS is the stronger, more informative analyst-facing
# conclusion, so it is checked first and does not depend on input.status.
decision := {
    "conclusion": "MALICIOUS",
    "destination": "quarantine",
    "review_required": true,
    "reasons": ["ClamAV detected malware."],
} if {
    input.clamav.status == "complete"
    input.clamav.detected == true
} else := {
    "conclusion": "INCOMPLETE",
    "destination": "quarantine",
    "review_required": true,
    "reasons": ["Normalized static evidence is incomplete."],
} if {
    input.status == "incomplete"
} else := {
    "conclusion": "SUSPICIOUS",
    "destination": "quarantine",
    "review_required": true,
    "reasons": ["YARA matched one or more rules with no stronger malware detection."],
} if {
    input.yara.status == "complete"
    count(input.yara.matches) > 0
} else := {
    "conclusion": "CLEAN",
    "destination": "clean",
    "review_required": false,
    "reasons": ["Required static analysis completed with no blocking findings."],
} if {
    input.status == "complete"
    input.clamav.status == "complete"
    input.clamav.detected == false
    input.yara.status == "complete"
    count(input.yara.matches) == 0
    count(input.errors) == 0
    count(input.warnings) == 0
} else := {
    "conclusion": "INCOMPLETE",
    "destination": "quarantine",
    "review_required": true,
    "reasons": ["No disposition rule matched; quarantined by default."],
}
