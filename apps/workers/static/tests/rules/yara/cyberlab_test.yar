/* Test-only rules (mounted via STATIC_YARA_TEST_RULES; never baked into the image). */

rule CyberLab_Test_Marker : test
{
    meta:
        description = "CyberLab synthetic test marker string"
        severity = "medium"
    strings:
        $marker = "CYBERLAB-STATIC-TEST-MARKER-7f3a" ascii wide
    condition:
        $marker
}

rule CyberLab_Test_Unlisted_High : test
{
    meta:
        description = "Claims high severity but is not allowlisted (must be capped at low)"
        severity = "high"
    strings:
        $marker = "CYBERLAB-SEVERITY-CLAMP-TEST" ascii
    condition:
        $marker
}
