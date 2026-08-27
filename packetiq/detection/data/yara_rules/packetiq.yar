/*
 * PacketIQ bundled example YARA rules.
 *
 * These are intentionally generic, safe, high-signal detections for content
 * carried in network traffic. Add your own rules by pointing
 * PACKETIQ_YARA_RULES at a file or directory of .yar/.yara files.
 *
 * A detection rule has to contain the thing it detects, which makes a rule file
 * look like a specimen to a desktop anti-virus scanner — and a quarantined
 * download is a rule set nobody gets to run. Where a pattern is a complete,
 * universally-flagged signature it is therefore written as bytes rather than as
 * a quoted string: identical matching, nothing for a scanner to lift out. The
 * webshell and cradle patterns below are deliberately *fragments* (`eval($_POST`
 * with no `<?php`), which is both better detection and not a runnable anything.
 */

rule EICAR_Test_File
{
    meta:
        description = "EICAR anti-malware test file"
        severity = "high"
        note = "Pattern written as bytes, not ASCII, on purpose — see the header."
    strings:
        // The EICAR string, byte for byte. Spelling it in hex rather than as a
        // quoted literal matches exactly the same 68 bytes while keeping this
        // rule file from being a specimen of what it detects.
        $eicar = {
            58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35
            34 28 50 5E 29 37 43 43 29 37 7D 24 45 49 43 41
            52 2D 53 54 41 4E 44 41 52 44 2D 41 4E 54 49 56
            49 52 55 53 2D 54 45 53 54 2D 46 49 4C 45 21 24
            48 2B 48 2A
        }
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
