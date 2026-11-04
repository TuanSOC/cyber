/*
 * CyberLab baseline YARA rules (in-house, written for this project; same licence as the repo).
 *
 * Deliberately small and benign-safe: structural markers and API-name sets an analyst wants
 * pointed out, not family signatures. Every rule carries `description` and `severity`
 * meta. The worker caps severity at `low` unless the rule is on its allowlist
 * (static_worker/detections/signatures.py). High entropy / packing heuristics live in the
 * heuristic detectors, not here.
 */

import "pe"

rule CyberLab_UPX_Section_Names : packer
{
    meta:
        description = "Section names used by the UPX packer (UPX0/UPX1/UPX2)"
        severity = "low"
    condition:
        pe.is_pe and for any s in pe.sections : (
            s.name == "UPX0" or s.name == "UPX1" or s.name == "UPX2"
        )
}

rule CyberLab_UPX_Marker_String : packer
{
    meta:
        description = "UPX packer marker string with a UPX-named section"
        severity = "low"
    strings:
        $upx = "UPX!" ascii
    condition:
        pe.is_pe and $upx and for any s in pe.sections : (s.name == "UPX1")
}

rule CyberLab_Embedded_PE_In_Overlay : embedded
{
    meta:
        description = "Overlay data starts with a complete PE header (embedded executable)"
        severity = "medium"
    condition:
        pe.is_pe and pe.overlay.size > 0x40
        and uint16(pe.overlay.offset) == 0x5A4D
        and uint32(pe.overlay.offset + uint32(pe.overlay.offset + 0x3C)) == 0x00004550
}

rule CyberLab_Embedded_PE_In_Resource : embedded
{
    meta:
        description = "A resource starts with a complete PE header (embedded executable)"
        severity = "medium"
    condition:
        pe.is_pe and for any r in pe.resources : (
            r.length > 0x40
            and uint16(r.offset) == 0x5A4D
            and uint32(r.offset + uint32(r.offset + 0x3C)) == 0x00004550
        )
}

rule CyberLab_Process_Injection_API_Names : api
{
    meta:
        description = "Names of the classic remote-process write-and-execute API set"
        severity = "low"
    strings:
        $alloc = "VirtualAllocEx" ascii wide
        $write = "WriteProcessMemory" ascii wide
        $thread = "CreateRemoteThread" ascii wide
        $apc = "QueueUserAPC" ascii wide
        $ctx = "SetThreadContext" ascii wide
        $unmap = "NtUnmapViewOfSection" ascii wide
    condition:
        uint16(0) == 0x5A4D and $write and ($alloc or $unmap) and ($thread or $apc or $ctx)
}

rule CyberLab_Keyboard_Hook_API_Names : api
{
    meta:
        description = "Names of keyboard hooking / key-state polling APIs"
        severity = "low"
    strings:
        $hook_a = "SetWindowsHookExA" ascii wide
        $hook_w = "SetWindowsHookExW" ascii wide
        $async = "GetAsyncKeyState" ascii wide
        $state = "GetKeyState" ascii wide
        $board = "GetKeyboardState" ascii wide
    condition:
        uint16(0) == 0x5A4D and ($hook_a or $hook_w) and ($async or $state or $board)
}
