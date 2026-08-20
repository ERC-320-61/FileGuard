rule FileGuard_Harmless_Text_Marker
{
    meta:
        description = "Matches a harmless FileGuard PoC text marker"
        author = "FileGuard"
        severity = "low"
        confidence = 90

    strings:
        $marker = "FILEGUARD_HARMLESS_TEST"

    condition:
        $marker
}

rule FileGuard_Harmless_Secondary_Marker
{
    meta:
        description = "Second harmless marker used to test multiple matches"
        author = "FileGuard"
        severity = "informational"
        confidence = 100

    strings:
        $marker = "FILEGUARD_SECOND_TEST"

    condition:
        $marker
}
