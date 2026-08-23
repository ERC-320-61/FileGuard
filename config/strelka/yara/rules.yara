rule FileGuard_Harmless_Test_Marker
{
    strings:
        $marker = "FILEGUARD_YARA_TEST"

    condition:
        $marker
}