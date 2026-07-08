/*
 * PacketIQ bundled example YARA rules.
 *
 * These are intentionally generic, safe, high-signal detections for content
 * carried in network traffic. Add your own rules by pointing
 * PACKETIQ_YARA_RULES at a file or directory of .yar/.yara files.
 */

rule EICAR_Test_File
{
    meta:
        description = "EICAR anti-malware test file"
        severity = "high"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Base64_Encoded_PE
{
    meta:
        description = "Base64-encoded Windows PE (MZ header) — common in droppers/loaders"
        severity = "high"
    strings:
        $b64mz = "TVqQAAMAAAAEAAAA"   // base64 of a standard MZ DOS header
        $b64mz2 = "TVpQAAIAAAAEAA"
    condition:
        any of them
}

rule Generic_Webshell_Markers
{
    meta:
        description = "Generic PHP/JSP webshell markers seen in HTTP bodies"
        severity = "high"
    strings:
        $php1 = "eval($_POST" nocase
        $php2 = "eval($_GET" nocase
        $php3 = "system($_REQUEST" nocase
        $php4 = "shell_exec(" nocase
        $jsp1 = "Runtime.getRuntime().exec(" nocase
        $asp1 = "Server.CreateObject(\"WScript.Shell\")" nocase
    condition:
        any of them
}

rule PowerShell_Download_Cradle
{
    meta:
        description = "PowerShell download/exec cradle (often used by loaders over HTTP)"
        severity = "medium"
    strings:
        $a = "IEX(New-Object Net.WebClient).DownloadString" nocase
        $b = "Invoke-Expression" nocase
        $c = "FromBase64String" nocase
        $d = "-EncodedCommand" nocase
    condition:
        2 of them
}
