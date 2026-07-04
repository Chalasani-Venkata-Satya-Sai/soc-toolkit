/*
    Sample YARA rules for SOC Toolkit demo/testing purposes.
    These are intentionally broad, illustrative heuristics (based on
    widely published community patterns) — replace/extend with your
    organization's curated rule set (e.g. from YARA-Rules or Neo23x0/signature-base)
    for real production hunting.
*/

rule Suspicious_Double_Extension
{
    meta:
        description = "Filename uses a double extension often used to disguise executables"
        severity = "medium"
        author = "soc-toolkit"
    strings:
        $a = ".pdf.exe" nocase
        $b = ".doc.exe" nocase
        $c = ".jpg.exe" nocase
        $d = ".txt.exe" nocase
    condition:
        any of them
}

rule Suspicious_PowerShell_EncodedCommand
{
    meta:
        description = "Contains an encoded/obfuscated PowerShell invocation, common in fileless malware"
        severity = "high"
        author = "soc-toolkit"
    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
        $hidden = "-WindowStyle Hidden" nocase
    condition:
        2 of them
}

rule Suspicious_Credential_Dumping_Strings
{
    meta:
        description = "Strings associated with common credential-dumping tooling"
        severity = "critical"
        author = "soc-toolkit"
    strings:
        $s1 = "sekurlsa::logonpasswords" nocase
        $s2 = "lsadump::sam" nocase
        $s3 = "mimikatz" nocase
    condition:
        any of them
}

rule Suspicious_Macro_AutoExec
{
    meta:
        description = "Office macro with auto-executing subroutines often used in phishing payloads"
        severity = "medium"
        author = "soc-toolkit"
    strings:
        $a1 = "AutoOpen" nocase
        $a2 = "Document_Open" nocase
        $a3 = "Auto_Open" nocase
        $shell = "Shell(" nocase
    condition:
        (1 of ($a*)) and $shell
}

rule Generic_Reverse_Shell_Indicators
{
    meta:
        description = "Common code fragments used to establish reverse shells"
        severity = "high"
        author = "soc-toolkit"
    strings:
        $py = "socket.socket(socket.AF_INET" nocase
        $bash = "/dev/tcp/" nocase
        $nc = "nc -e /bin/sh" nocase
    condition:
        any of them
}
