<#
  Qwen Phone-Home Shield (Windows)
  https://github.com/BITNBIT/qwen-phonehome-shield

  Protects a PC against the Qwen3.8 "phone home" incident (Cohere, 26 Oct 2026):
    1. hosts file: sinkholes ONLY the exact object-storage hosts seen in the published traces
       (no wildcard, no whole aliyuncs.com: normal websites keep working)
    2. Windows Firewall: blocks outbound traffic to the cloud-metadata IPs 169.254.169.254 and
       100.100.100.200 (skipped automatically on virtual / cloud machines, where they are needed)
    3. scan: lists the Qwen3.8 models on this PC (Ollama, LM Studio, Hugging Face cache, any .gguf)

  Everything is marked and fully reversible: Enable-Shield.bat / Disable-Shield.bat
  Usage:  QwenShield.ps1 [-Action Enable|Disable|Scan] [-HostsPath <file>] [-NoFirewall] [-NoDriveScan]
#>
param(
    [ValidateSet("Enable", "Disable", "Scan")] [string]$Action = "Enable",
    [string]$HostsPath = "$env:SystemRoot\System32\drivers\etc\hosts",
    [switch]$NoFirewall,
    [switch]$NoDriveScan
)

$ErrorActionPreference = "Stop"
$Version = "1.0.0"
$Start = "# >>> qwen-phonehome-shield >>> (do not edit this block; remove it with Disable-Shield.bat)"
$End = "# <<< qwen-phonehome-shield <<<"
$FwGroup = "Qwen Phone-Home Shield"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Hosts named in Cohere's blog post, trace dataset and in the public reproductions (see README, "Sources").
# Only exact bucket/proxy hostnames: blocking them cannot break normal browsing or Alibaba Cloud in general.
$Hosts = @(
    "sanmaohe.oss-cn-beijing.aliyuncs.com",                      # upload target in Cohere's sandbox trace
    "routify-file-proxy-sg.oss-ap-southeast-1.aliyuncs.com",     # file proxy, most frequent host (still live)
    "routify-file-proxy-sg.oss-ap-southeast-1-internal.aliyuncs.com",
    "routify-file-proxy-sg.oss-accelerate.aliyuncs.com",
    "sanmaoheihei-oss.oss-cn-beijing.aliyuncs.com",
    "r8-detect-deps.oss-us-east-1.aliyuncs.com",
    "r001-cs.oss-cn-hangzhou.aliyuncs.com",
    "rumo.oss-cn-qingdao.aliyuncs.com",
    "rally9-high-9200.oss-cn-shanghai.aliyuncs.com",
    "r0ck3t-upload.oss-cn-hangzhou.aliyuncs.com",
    "detection-objects-x9k2m3v7p1q4.oss-cn-hangzhou.aliyuncs.com",
    "eval-llm-1.oss-ap-southeast-1.aliyuncs.com",
    "rce-testing-bucket-711.s3.us-west-2.amazonaws.com",
    "lattice-gtm-files.s3-website-us-east-1.amazonaws.com",
    "r0bodycti01.blob.core.windows.net",
    "tempfiles.xty.cc",
    "probe.tmpfiles.org",
    "r0ck3t.net",
    "r0body.com",
    "r0cb35.com"
)
$MetadataIPs = @("169.254.169.254", "100.100.100.200")
$ModelPattern = "qwen[-_ .]?3[._]8"

function Say($text, $color = "Gray") { Write-Host $text -ForegroundColor $color }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-CloudOrVM {
    # on cloud servers the metadata IP is needed (credentials, network setup): never block it there
    try {
        $cs = Get-CimInstance Win32_ComputerSystem
        $bios = Get-CimInstance Win32_BIOS
        $text = "$($cs.Manufacturer) $($cs.Model) $($bios.Manufacturer) $($bios.SMBIOSBIOSVersion) $($bios.SerialNumber)"
        return $text -match "Amazon|EC2|Google|Alibaba|Aliyun|Virtual Machine|VMware|VirtualBox|KVM|QEMU|Xen|OpenStack|DigitalOcean|Hetzner|Oracle|Bochs|Parallels"
    } catch { return $true }
}

# The hosts file is handled as raw bytes (Latin-1 maps every byte 1:1), so Disable gives back the
# file exactly as it was, byte for byte, whatever its encoding and line endings.
$Latin1 = [System.Text.Encoding]::GetEncoding(28591)

function Read-HostsText {
    if (-not (Test-Path $HostsPath)) { return "" }
    return $Latin1.GetString([System.IO.File]::ReadAllBytes($HostsPath))
}

function Write-HostsText($text) {
    [System.IO.File]::WriteAllBytes($HostsPath, $Latin1.GetBytes($text))
}

function Remove-Block($text) {
    # removes exactly the segment that Enable appended: "`r`n" + block + "`r`n"
    $pattern = "\r?\n?" + [regex]::Escape($Start) + "[\s\S]*?" + [regex]::Escape($End) + "\r?\n?"
    return [regex]::Replace($text, $pattern, "")
}

function Clear-Dns { try { ipconfig /flushdns | Out-Null } catch { } }

function Install-Shield {
    Say "`n[1/3] hosts file: $HostsPath" Cyan
    $backup = "$HostsPath.qwenshield.bak"
    if ((Test-Path $HostsPath) -and -not (Test-Path $backup)) {
        Copy-Item -LiteralPath $HostsPath -Destination $backup
        Say "      backup saved: $backup"
    }
    $block = @($Start, "# Qwen3.8 phone-home incident (Oct 2026) - v$Version - https://github.com/BITNBIT/qwen-phonehome-shield")
    $block += $Hosts | ForEach-Object { "0.0.0.0 $_" }
    $block += $End
    Write-HostsText ((Remove-Block (Read-HostsText)) + "`r`n" + ($block -join "`r`n") + "`r`n")
    Clear-Dns
    Say "      $($Hosts.Count) hosts blocked (0.0.0.0), DNS cache cleared" Green

    Say "`n[2/3] firewall: cloud-metadata addresses $($MetadataIPs -join ', ')" Cyan
    if ($NoFirewall) {
        Say "      skipped (-NoFirewall)" Yellow
    } elseif (Test-CloudOrVM) {
        Say "      skipped: this looks like a virtual/cloud machine, where these addresses are needed" Yellow
    } else {
        Get-NetFirewallRule -Group $FwGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -DisplayName "Qwen Shield - block cloud metadata IPs" -Group $FwGroup `
            -Direction Outbound -Action Block -RemoteAddress $MetadataIPs -Profile Any `
            -Description "Qwen3.8 phone-home incident: a home PC never needs these addresses. Remove with Disable-Shield.bat." | Out-Null
        Say "      outbound rule added" Green
    }
}

function Uninstall-Shield {
    Say "`nDisabling Qwen Phone-Home Shield" Cyan
    $text = Read-HostsText
    if ($text.Contains($Start)) {
        Write-HostsText (Remove-Block $text)
        Clear-Dns
        Say "  hosts block removed (the rest of the file is untouched)" Green
    } else {
        Say "  hosts file: nothing to remove"
    }
    $rules = Get-NetFirewallRule -Group $FwGroup -ErrorAction SilentlyContinue
    if ($rules) { $rules | Remove-NetFirewallRule; Say "  firewall rule removed" Green } else { Say "  firewall: nothing to remove" }
}

function Test-GgufIsQwen38($path) {
    if ($path -match $ModelPattern) { return $true }
    try {
        # GGUF metadata (general.name / general.basename) is at the beginning of the file
        $fs = [System.IO.File]::OpenRead($path)
        try {
            $buf = New-Object byte[] ([Math]::Min(4MB, $fs.Length))
            [void]$fs.Read($buf, 0, $buf.Length)
        } finally { $fs.Close() }
        $text = [System.Text.Encoding]::GetEncoding(28591).GetString($buf)
        return $text -match "general\.(base)?name.{0,24}$ModelPattern"
    } catch { return $false }
}

function Find-Qwen38 {
    $found = New-Object System.Collections.Generic.List[string]
    $homeDir = $env:USERPROFILE

    # Ollama (manifests are named after the model tag)
    $ollama = @($env:OLLAMA_MODELS, "$homeDir\.ollama\models") | Where-Object { $_ -and (Test-Path $_) }
    foreach ($o in $ollama) {
        Get-ChildItem -LiteralPath (Join-Path $o "manifests") -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match $ModelPattern } |
            ForEach-Object { $found.Add("Ollama     $($_.FullName.Substring((Join-Path $o 'manifests').Length + 1))") }
    }
    # Hugging Face cache (transformers, vLLM, llama.cpp -hf ...)
    $hf = @($(if ($env:HF_HOME) { Join-Path $env:HF_HOME "hub" }), $env:HF_HUB_CACHE, "$homeDir\.cache\huggingface\hub") |
        Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
    foreach ($h in $hf) {
        Get-ChildItem -LiteralPath $h -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match $ModelPattern } | ForEach-Object { $found.Add("HF cache   $($_.FullName)") }
    }
    # every .gguf on the fixed drives (LM Studio, llama.cpp, Jan, GPT4All, KoboldCpp, custom folders...)
    $roots = if ($NoDriveScan) {
        @("$homeDir\.lmstudio", "$homeDir\.cache\lm-studio", "$homeDir\AppData\Roaming\Jan", "$homeDir\Downloads") | Where-Object { Test-Path $_ }
    } else {
        Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object { $_.DeviceID + "\" }
    }
    foreach ($r in $roots) {
        Say "      searching .gguf files in $r ..."
        Get-ChildItem -LiteralPath $r -Recurse -File -Filter *.gguf -ErrorAction SilentlyContinue |
            Where-Object { Test-GgufIsQwen38 $_.FullName } |
            ForEach-Object { $found.Add("GGUF       $($_.FullName)") }
    }
    return $found | Select-Object -Unique
}

function Show-Scan {
    Say "`n[scan] Qwen3.8 models on this PC" Cyan
    $models = @(Find-Qwen38)
    $report = New-Object System.Collections.Generic.List[string]
    $report.Add("Qwen Phone-Home Shield v$Version - report $(Get-Date -Format 'yyyy-MM-dd HH:mm')")
    $report.Add("")
    if ($models.Count -eq 0) {
        Say "      no Qwen3.8 model found" Green
        $report.Add("No Qwen3.8 model found.")
    } else {
        Say "      found $($models.Count):" Yellow
        $models | ForEach-Object { Say "        $_" Yellow; $report.Add($_) }
        $report.Add("")
        foreach ($t in @(
            "These models are SAFE to keep and to use for chat, writing, vision, translation.",
            "The incident only matters when the model can ACT: agents with shell, code execution,",
            "web/HTTP tools or a browser (Open WebUI tools, Cline, Aider, OpenHands, opencode, custom agents).",
            "With those: allow only the tools you need, ask for confirmation before commands,",
            "and never give the agent cloud credentials.")) { Say "      $t"; $report.Add($t) }
    }
    $state = if ((Read-HostsText).Contains($Start)) { "ACTIVE" } else { "not installed" }
    $report.Add(""); $report.Add("Shield: $state")
    Say "`n      shield: $state" $(if ($state -eq "ACTIVE") { "Green" } else { "Yellow" })
    $desk = [Environment]::GetFolderPath("Desktop")
    $out = Join-Path $(if ($desk -and (Test-Path $desk)) { $desk } else { $ScriptDir }) "QwenShield-report.txt"
    $report | Set-Content -LiteralPath $out -Encoding UTF8
    Say "      report saved: $out"
}

Say "Qwen Phone-Home Shield v$Version" White
if ($Action -ne "Scan" -and $HostsPath -eq "$env:SystemRoot\System32\drivers\etc\hosts" -and -not (Test-Admin)) {
    Say "Administrator rights are needed: start it with Enable-Shield.bat / Disable-Shield.bat (double click)." Red
    exit 1
}
switch ($Action) {
    "Enable" { Install-Shield; Show-Scan; Say "`nShield ENABLED. Turn it off at any time with Disable-Shield.bat." Green }
    "Disable" { Uninstall-Shield; Say "`nShield DISABLED. Your PC is exactly as before." Green }
    "Scan" { Show-Scan }
}
