package fileguard.disposition

# Stable conclusion vocabulary for FileGuard disposition policies.
supported_conclusions := {"CLEAN", "SUSPICIOUS", "MALICIOUS", "INCOMPLETE"}

# Until more disposition rules are implemented, unmatched evidence fails closed.
default decision := {
    "conclusion": "INCOMPLETE",
    "destination": "quarantine",
    "review_required": true,
    "reasons": ["No disposition rule matched; quarantined by default."],
}

decision := {
    "conclusion": "INCOMPLETE",
    "destination": "quarantine",
    "review_required": true,
    "reasons": ["Normalized static evidence is incomplete."],
} if {
    input.status == "incomplete"
}

decision := {
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
}
