<#
  Qwen Phone-Home Shield 2 (Windows) - https://github.com/BITNBIT/qwen-phonehome-shield

  1. Known hosts of the Qwen3.8 phone-home incident: always blocked (hosts file).
  2. AI Connection Guard: when a local AI program (llama.cpp, Ollama, LM Studio, KoboldCpp, Jan, your
     agents...) tries to reach a NEW internet address, a window asks you first:
         Accept only now | Accept always | No, not accepted | No, never
     and shows WHICH model is running and WHERE it wants to go.
       Mode A (Windows Firewall active): nothing leaves until you accept.
       Mode B (third-party firewall, e.g. Norton): the connection is cut at once and you are asked.
  3. Your own lists: allowed.txt / blocked.txt / programs.txt in %ProgramData%\QwenShield
  4. Scan: lists the Qwen3.8 models on this PC.

  Nothing is ever sent anywhere by this program: no telemetry, no update check. Host names are
  read from the PC's own DNS cache. Everything is reversible with Disable-Shield.bat.

  Usage: QwenShield.ps1 -Action Enable|Disable|Scan|Manage|Status|Watch [-NoGuard] [-NoDriveScan]
#>
param(
    [ValidateSet("Enable", "Disable", "Scan", "Manage", "Status", "Watch", "Demo")] [string]$Action = "Enable",
    [string]$HostsPath = "$env:SystemRoot\System32\drivers\etc\hosts",
    [switch]$NoFirewall,
    [switch]$NoDriveScan,
    [switch]$NoGuard,
    [string]$TestAnswer = "",     # tests only: answer the dialog automatically (once|always|no|never)
    [string]$DemoPng = ""         # Demo: save the dialog as a picture (README screenshot)
)

$ErrorActionPreference = "Stop"
$Version = "2.0.0"
$Repo = "https://github.com/BITNBIT/qwen-phonehome-shield"
$Start = "# >>> qwen-phonehome-shield >>> (do not edit this block; remove it with Disable-Shield.bat)"
$End = "# <<< qwen-phonehome-shield <<<"
$GStart = "# >>> qwen-phonehome-shield guard >>> (sites you blocked with 'No, never')"
$GEnd = "# <<< qwen-phonehome-shield guard <<<"
$FwGroup = "Qwen Phone-Home Shield"
$GuardGroup = "Qwen Phone-Home Shield Guard"
$TaskName = "Qwen Phone-Home Shield Guard"
$Data = Join-Path $env:ProgramData "QwenShield"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$WfpAudit = "{0CCE9226-69AE-11D9-BED3-505054503030}"   # "Filtering Platform Connection" (language independent)
$script:IT = if ($env:QWENSHIELD_LANG) { $env:QWENSHIELD_LANG -eq "it" } else { (Get-UICulture).TwoLetterISOLanguageName -eq "it" }
function T($testoIt, $textEn) { if ($script:IT) { $testoIt } else { $textEn } }

# Hosts named in Cohere's blog post, trace dataset and public reproductions (see README, "Sources").
$Hosts = @(
    "sanmaohe.oss-cn-beijing.aliyuncs.com",
    "routify-file-proxy-sg.oss-ap-southeast-1.aliyuncs.com",
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
# shown in red in the dialog: online file storage and the addresses of the incident
$Suspicious = "aliyuncs\.com|oss-|\.s3[.-]|amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com|tmpfiles|tempfiles|paste|transfer\.sh|file\.io|anonfiles|routify|^169\.254\.169\.254$|^100\.100\.100\.200$"
$ModelPattern = "qwen[-_ .]?3[._]8"
# local AI engines and apps found automatically (you can add any other program, e.g. your agent)
$AiExe = @("ollama.exe", "ollama app.exe", "llama-server.exe", "llama-cli.exe", "llama-swap.exe", "LM Studio.exe", "lms.exe",
           "koboldcpp.exe", "koboldcpp_cu12.exe", "koboldcpp_nocuda.exe", "Jan.exe", "Msty.exe", "AnythingLLM.exe", "local-ai.exe")
# never asked: this PC, your local network
$AlwaysOk = @("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fe80::/10", "fc00::/7")

Add-Type -ReferencedAssemblies System.Numerics -TypeDefinition @"
using System; using System.Collections.Generic; using System.IO; using System.Net; using System.Numerics;
using System.Runtime.InteropServices; using System.Text;
namespace QS {
public static class N {
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern uint QueryDosDevice(string dev, StringBuilder target, int max);
  [StructLayout(LayoutKind.Sequential)] struct ROW { public uint State, LAddr, LPort, RAddr, RPort; }
  [DllImport("iphlpapi.dll")] static extern int SetTcpEntry(ref ROW row);
  static Dictionary<string, string> map;
  // "\device\harddiskvolume4\x\y.exe" (firewall log) -> "E:\x\y.exe"
  public static string DosPath(string p) {
    if (string.IsNullOrEmpty(p)) return p;
    if (map == null) {
      map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
      foreach (var d in Environment.GetLogicalDrives()) {
        var l = d.Substring(0, 2); var sb = new StringBuilder(1024);
        if (QueryDosDevice(l, sb, 1024) > 0) map[sb.ToString()] = l;
      }
    }
    foreach (var kv in map)
      if (p.StartsWith(kv.Key + "\\", StringComparison.OrdinalIgnoreCase)) return kv.Value + p.Substring(kv.Key.Length);
    return p;
  }
  // cuts an IPv4 TCP connection at once (administrator)
  public static int KillTcp(string lip, int lport, string rip, int rport) {
    var r = new ROW(); r.State = 12;
    r.LAddr = BitConverter.ToUInt32(IPAddress.Parse(lip).GetAddressBytes(), 0);
    r.LPort = (uint)(((lport & 0xFF) << 8) | ((lport >> 8) & 0xFF));
    r.RAddr = BitConverter.ToUInt32(IPAddress.Parse(rip).GetAddressBytes(), 0);
    r.RPort = (uint)(((rport & 0xFF) << 8) | ((rport >> 8) & 0xFF));
    return SetTcpEntry(ref r);
  }
  [DllImport("ntdll.dll")] static extern int NtSuspendProcess(IntPtr h);
  [DllImport("ntdll.dll")] static extern int NtResumeProcess(IntPtr h);
  public static void Pause(int pid, bool on) {
    using (var p = System.Diagnostics.Process.GetProcessById(pid)) { if (on) NtSuspendProcess(p.Handle); else NtResumeProcess(p.Handle); }
  }
  public static List<string> Find(string[] roots, string[] names, string ext) {
    var set = new HashSet<string>(names, StringComparer.OrdinalIgnoreCase);
    var skip = new HashSet<string>(new[] { "`$Recycle.Bin", "System Volume Information", "WinSxS", "Windows.old" }, StringComparer.OrdinalIgnoreCase);
    var res = new List<string>(); var st = new Stack<string>(roots);
    while (st.Count > 0) {
      var d = st.Pop();
      try { foreach (var f in Directory.GetFiles(d)) { var n = Path.GetFileName(f);
        if (set.Contains(n) || n.EndsWith(ext, StringComparison.OrdinalIgnoreCase) ||
            (n.StartsWith("koboldcpp", StringComparison.OrdinalIgnoreCase) && n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))) res.Add(f); } } catch { }
      try { foreach (var s in Directory.GetDirectories(d)) {
        if (skip.Contains(Path.GetFileName(s))) continue;
        try { if ((File.GetAttributes(s) & FileAttributes.ReparsePoint) != 0) continue; } catch { continue; }
        st.Push(s); } } catch { }
    }
    return res;
  }
  static BigInteger Big(IPAddress ip) { var b = ip.GetAddressBytes(); Array.Reverse(b); var c = new byte[b.Length + 1]; Array.Copy(b, c, b.Length); return new BigInteger(c); }
  static string Ip(BigInteger v, bool six) { int len = six ? 16 : 4; var b = v.ToByteArray(); var o = new byte[len];
    for (int i = 0; i < len && i < b.Length; i++) o[i] = b[i]; Array.Reverse(o); return new IPAddress(o).ToString(); }
  static bool Parse(string s, out BigInteger lo, out BigInteger hi, out bool six) {
    s = s.Trim(); int z = s.IndexOf('%'); if (z > 0) s = s.Substring(0, z);
    lo = hi = 0; six = false; IPAddress a, b;
    if (s.Contains("/")) { var p = s.Split('/'); if (!IPAddress.TryParse(p[0], out a)) return false;
      six = a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6; int pre;
      if (!int.TryParse(p[1], out pre)) return false; var size = BigInteger.Pow(2, (six ? 128 : 32) - pre);
      var v = Big(a); lo = v - (v % size); hi = lo + size - 1; return true; }
    if (s.Contains("-")) { var p = s.Split('-'); if (!IPAddress.TryParse(p[0], out a) || !IPAddress.TryParse(p[1], out b)) return false;
      six = a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6; lo = Big(a); hi = Big(b); return true; }
    if (!IPAddress.TryParse(s, out a)) return false;
    six = a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6; lo = hi = Big(a); return true;
  }
  public static bool IsIp(string s) { BigInteger l, h; bool x; return Parse(s, out l, out h, out x); }
  public static bool InRange(string ip, string range) {
    BigInteger a, b, l, h; bool s1, s2;
    if (!Parse(ip, out a, out b, out s1) || !Parse(range, out l, out h, out s2) || s1 != s2) return false;
    return a >= l && a <= h;
  }
  // everything except the allowed addresses = what the firewall rule blocks
  public static string[] Complement(string[] allowed) {
    var v4 = new List<BigInteger[]>(); var v6 = new List<BigInteger[]>();
    foreach (var s in allowed) { BigInteger l, h; bool six; if (s != null && Parse(s, out l, out h, out six)) (six ? v6 : v4).Add(new[] { l, h }); }
    var res = new List<string>(); Gaps(v4, false, res); Gaps(v6, true, res); return res.ToArray();
  }
  static void Gaps(List<BigInteger[]> r, bool six, List<string> res) {
    var max = BigInteger.Pow(2, six ? 128 : 32) - 1; r.Sort((x, y) => x[0].CompareTo(y[0])); BigInteger cur = 0;
    foreach (var x in r) { if (x[0] > cur) res.Add(Ip(cur, six) + "-" + Ip(x[0] - 1, six)); if (x[1] + 1 > cur) cur = x[1] + 1; }
    if (cur <= max) res.Add(Ip(cur, six) + "-" + Ip(max, six));
  }
}}
"@

function Say($text, $color = "Gray") { if ($Action -ne "Watch") { Write-Host $text -ForegroundColor $color } }

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

function Get-OtherFirewall {
    # a third-party firewall (Norton, Kaspersky, Bitdefender, ESET...) switches off the Windows Firewall rules
    try {
        $on = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct -ErrorAction Stop |
            Where-Object { ($_.productState -band 0x1000) -ne 0 -and $_.displayName -notmatch "Windows" }
        if ($on) { return @($on)[0].displayName }
    } catch { }
    if (-not (Get-NetFirewallProfile | Where-Object { $_.Enabled })) { return "(Windows Firewall off)" }
    return $null
}

function Get-Mode { if (Get-OtherFirewall) { "B" } else { "A" } }

# ---------------------------------------------------------------- hosts file (byte-exact, reversible)
$Latin1 = [System.Text.Encoding]::GetEncoding(28591)
function Read-HostsText { if (-not (Test-Path $HostsPath)) { return "" }; $Latin1.GetString([System.IO.File]::ReadAllBytes($HostsPath)) }
function Write-HostsText($text) { [System.IO.File]::WriteAllBytes($HostsPath, $Latin1.GetBytes($text)) }
function Remove-Block($text, $s = $Start, $e = $End) {
    # removes exactly the segment that was appended: "`r`n" + block + "`r`n"
    [regex]::Replace($text, "\r?\n?" + [regex]::Escape($s) + "[\s\S]*?" + [regex]::Escape($e) + "\r?\n?", "")
}
function Clear-Dns { try { ipconfig /flushdns | Out-Null } catch { } }

function Set-GuardHosts {
    # sites marked "No, never" are also sinkholed by name (works with any firewall)
    $names = @(Read-List "blocked.txt" | Where-Object { -not [QS.N]::IsIp($_) -and -not $_.StartsWith("*") })
    $text = Remove-Block (Read-HostsText) $GStart $GEnd
    if ($names.Count) { $text += "`r`n" + (@($GStart) + ($names | ForEach-Object { "0.0.0.0 $_" }) + $GEnd -join "`r`n") + "`r`n" }
    Write-HostsText $text
    Clear-Dns
}

# ---------------------------------------------------------------- your lists
function Initialize-Data {
    New-Item -ItemType Directory -Force -Path $Data | Out-Null
    $heads = @{
        "allowed.txt"  = @("# $(T 'SITI AUTORIZZATI: i programmi AI possono collegarsi qui senza chiedere.' 'ALLOWED SITES: AI programs may connect here without asking.')",
                           "# $(T 'Uno per riga: nome (esempio.com), *.esempio.com (anche i sottodomini), IP o rete (10.1.2.0/24).' 'One per line: name (example.com), *.example.com (subdomains too), IP or network (10.1.2.0/24).')",
                           "# $(T '"Accetta sempre" scrive qui. Questo PC e la rete di casa sono sempre ammessi.' '"Accept always" writes here. This PC and your home network are always allowed.')")
        "blocked.txt"  = @("# $(T 'SITI BLOCCATI: mai, e senza chiedere. Stesso formato. "No, mai" scrive qui.' 'BLOCKED SITES: never, and without asking. Same format. "No, never" writes here.')")
        "programs.txt" = @("# $(T 'PROGRAMMI AI SORVEGLIATI: percorso completo del .exe, uno per riga (aggiungi qui i tuoi agenti).' 'GUARDED AI PROGRAMS: full path of the .exe, one per line (add your agents here).')")
    }
    foreach ($f in $heads.Keys) {
        $p = Join-Path $Data $f
        if (-not (Test-Path $p)) { $heads[$f] | Set-Content -LiteralPath $p -Encoding UTF8 }
    }
}
function Read-List($name) {
    $p = Join-Path $Data $name
    if (-not (Test-Path $p)) { return @() }
    @(Get-Content -LiteralPath $p -Encoding UTF8 | ForEach-Object { ($_ -replace "#.*$", "").Trim() } | Where-Object { $_ })
}
function Add-ToList($name, $value) {
    if ((Read-List $name) -notcontains $value) { Add-Content -LiteralPath (Join-Path $Data $name) -Value $value -Encoding UTF8 }
}
function Test-Listed($entries, $hostName, $ip) {
    foreach ($e in $entries) {
        if ([QS.N]::IsIp($e) -or $e.Contains("/")) { if ($ip -and [QS.N]::InRange($ip, $e)) { return $true }; continue }
        if (-not $hostName) { continue }
        if ($e.StartsWith("*.")) { $d = $e.Substring(2); if ($hostName -ieq $d -or $hostName.EndsWith("." + $d, "OrdinalIgnoreCase")) { return $true } }
        elseif ($hostName -ieq $e) { return $true }
    }
    return $false
}
function Write-Log($text) {
    try { Add-Content -LiteralPath (Join-Path $Data "log.txt") -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $text" -Encoding UTF8 } catch { }
}

# ---------------------------------------------------------------- which model, which site
$script:DnsMemo = @{}
function Get-HostForIp($ip) {
    # only the PC's own DNS cache: nothing is asked on the network
    if ($script:DnsMemo.ContainsKey($ip)) { return $script:DnsMemo[$ip] }
    $name = $null
    try {
        $cache = @(Get-DnsClientCache -ErrorAction Stop)
        $rec = $cache | Where-Object { $_.Data -eq $ip } | Select-Object -First 1
        if ($rec) {
            $name = $rec.Entry
            # follow CNAME chains back to the name the program asked for
            for ($i = 0; $i -lt 5; $i++) {
                $up = $cache | Where-Object { $_.Type -eq 5 -and $_.Data -ieq $name } | Select-Object -First 1
                if (-not $up) { break }; $name = $up.Entry
            }
            # a site has several addresses: remember them all now, so one answer is valid for the whole site
            $cache | Where-Object { $_.Entry -ieq $rec.Entry -and $_.Type -in 1, 28 } | ForEach-Object { $script:DnsMemo[$_.Data] = $name }
        }
    } catch { }
    if ($name) { $script:DnsMemo[$ip] = $name }
    return $name
}

function Get-LocalModels($port) {
    # local OpenAI-compatible / Ollama servers say which model they run (only 127.0.0.1)
    foreach ($u in @("/running", "/api/ps", "/v1/models")) {
        try {
            $r = Invoke-RestMethod -Uri "http://127.0.0.1:$port$u" -TimeoutSec 2 -UseBasicParsing
            $names = @()
            if ($r.running) { $names = @($r.running | ForEach-Object { $_.model }) }
            elseif ($r.models) { $names = @($r.models | ForEach-Object { $_.name }) }
            elseif ($r.data) { $names = @($r.data | ForEach-Object { $_.id }) }
            $names = @($names | Where-Object { $_ })
            if ($names.Count) { return ($names | Select-Object -First 3) -join ", " }
        } catch { }
    }
    return $null
}

function Get-ModelName($procId, $depth = 0) {
    try { $cmd = (Get-CimInstance Win32_Process -Filter "ProcessId=$procId" -ErrorAction Stop).CommandLine } catch { $cmd = "" }
    if ($cmd -match '--alias\s+"([^"]+)"' -or $cmd -match "--alias\s+(\S+)") { return $Matches[1] }
    if ($cmd -match '(?:^|\s)(?:-m|--model)\s+"([^"]+)"' -or $cmd -match '(?:^|\s)(?:-m|--model)\s+(\S+)') {
        $m = $Matches[1]
        if ($m -match "sha256-([0-9a-f]{64})") {
            # Ollama runner: model blob -> name:tag from the manifests
            $digest = $Matches[1]
            foreach ($root in @($env:OLLAMA_MODELS, "$env:USERPROFILE\.ollama\models") | Where-Object { $_ }) {
                $man = Join-Path $root "manifests"
                if (-not (Test-Path $man)) { continue }
                $hit = Get-ChildItem -LiteralPath $man -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { (Get-Content -LiteralPath $_.FullName -Raw -ErrorAction SilentlyContinue) -match $digest } | Select-Object -First 1
                if ($hit) { return "$($hit.Directory.Name):$($hit.Name)" }
            }
        }
        return [IO.Path]::GetFileNameWithoutExtension(($m -replace '[\\/]+$', ''))
    }
    # a server listening here (Ollama, LM Studio, llama-swap...)
    foreach ($l in @(Get-NetTCPConnection -OwningProcess $procId -State Listen -ErrorAction SilentlyContinue | Select-Object -First 3)) {
        $n = Get-LocalModels $l.LocalPort
        if ($n) { return $n }
    }
    # an agent: follow its connections to the local AI server
    if ($depth -lt 2) {
        foreach ($c in @(Get-NetTCPConnection -OwningProcess $procId -State Established -ErrorAction SilentlyContinue |
                Where-Object { $_.RemoteAddress -in @("127.0.0.1", "::1") } | Select-Object -First 5)) {
            $srv = Get-NetTCPConnection -LocalPort $c.RemotePort -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($srv -and $srv.OwningProcess -ne $procId) {
                $n = Get-ModelName $srv.OwningProcess ($depth + 1)
                if (-not $n) { $n = Get-LocalModels $c.RemotePort }
                if ($n) { return $n }
            }
        }
    }
    return $null
}

# ---------------------------------------------------------------- the question window
function Show-Ask($model, $program, $hostName, $ip, $port, [switch]$Demo, [switch]$Paused) {
    if ($TestAnswer -and -not $Demo) { return $TestAnswer }
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $site = if ($hostName) { $hostName } else { $ip }
    $scheme = switch ($port) { 443 { "https://" } 80 { "http://" } default { "" } }
    $link = "$scheme$site" + $(if ($port -notin 80, 443) { ":$port" })
    $warn = ("$hostName $ip" -match $Suspicious)

    $f = New-Object System.Windows.Forms.Form
    $f.Text = "Qwen Phone-Home Shield"
    $f.StartPosition = "CenterScreen"; $f.TopMost = $true; $f.FormBorderStyle = "FixedDialog"
    $f.MaximizeBox = $false; $f.MinimizeBox = $false; $f.ShowInTaskbar = $true
    $f.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $f.BackColor = [System.Drawing.Color]::White
    $f.ClientSize = New-Object System.Drawing.Size(620, $(if ($warn) { 400 } else { 360 }))
    $f.Icon = [System.Drawing.SystemIcons]::Shield

    $y = 18
    $title = New-Object System.Windows.Forms.Label
    $title.Text = (T "La tua AI vuole collegarsi a internet" "Your AI wants to connect to the internet")
    $title.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 15)
    $title.ForeColor = [System.Drawing.Color]::FromArgb(176, 64, 0)
    $title.SetBounds(20, $y, 580, 34); $f.Controls.Add($title); $y += 46

    $rows = @(
        @((T "Modello" "Model"), $(if ($model) { $model } else { T "non riconosciuto" "not recognised" })),
        @((T "Programma" "Program"), $program),
        @((T "Vuole andare verso" "Wants to go to"), $link),
        @((T "Indirizzo" "Address"), "$ip  ($(T 'porta' 'port') $port)")
    )
    foreach ($r in $rows) {
        $k = New-Object System.Windows.Forms.Label
        $k.Text = $r[0]; $k.ForeColor = [System.Drawing.Color]::DimGray; $k.SetBounds(20, $y + 3, 150, 24); $f.Controls.Add($k)
        # read-only text: it can be copied, but never opened by mistake
        $v = New-Object System.Windows.Forms.TextBox
        $v.Text = $r[1]; $v.ReadOnly = $true; $v.BorderStyle = "None"; $v.BackColor = [System.Drawing.Color]::White
        $v.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 10.5); $v.SetBounds(170, $y + 3, 430, 24); $v.TabStop = $false
        $f.Controls.Add($v); $y += 32
    }
    if ($warn) {
        $w = New-Object System.Windows.Forms.Label
        $w.Text = (T "ATTENZIONE: è un deposito di file online o un indirizzo dell'incidente Qwen3.8." "WARNING: this is online file storage or an address from the Qwen3.8 incident.")
        $w.ForeColor = [System.Drawing.Color]::FromArgb(200, 0, 0); $w.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 10)
        $w.SetBounds(20, $y + 4, 580, 36); $f.Controls.Add($w); $y += 40
    }
    $q = New-Object System.Windows.Forms.Label
    $q.Text = (T "Sei consapevole? Vuoi autorizzare la connessione?" "Are you aware of this? Do you want to allow the connection?")
    $q.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 11); $q.SetBounds(20, $y + 8, 580, 26); $f.Controls.Add($q); $y += 46

    $script:answer = "no"
    $buttons = @(
        @((T "Accetta solo ora" "Accept only now"), "once", [System.Drawing.Color]::FromArgb(232, 245, 233)),
        @((T "Accetta sempre" "Accept always"), "always", [System.Drawing.Color]::FromArgb(200, 230, 201)),
        @((T "No, non accetto" "No, not accepted"), "no", [System.Drawing.Color]::FromArgb(255, 236, 179)),
        @((T "No, mai" "No, never"), "never", [System.Drawing.Color]::FromArgb(255, 205, 210))
    )
    $x = 20
    foreach ($b in $buttons) {
        $btn = New-Object System.Windows.Forms.Button
        $btn.Text = $b[0]; $btn.Tag = $b[1]; $btn.BackColor = $b[2]; $btn.FlatStyle = "Flat"
        $btn.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 10); $btn.SetBounds($x, $y, 138, 40)
        $btn.Add_Click({ param($s, $e) $script:answer = $s.Tag; $f.Close() })
        $f.Controls.Add($btn); $x += 146
        if ($b[1] -eq "no") { $f.AcceptButton = $btn; $f.CancelButton = $btn; $f.ActiveControl = $btn }
    }
    $y += 52
    $foot = New-Object System.Windows.Forms.Label
    $foot.Text = if ($Paused) { T "L'AI è in pausa finché non rispondi (IPv6). Se non accetti, il programma viene chiuso." "The AI is paused until you answer (IPv6). If you do not accept, the program is closed." } `
                 else { T "Finché non rispondi resta bloccata. Senza risposta in 2 minuti: No, non accetto." "It stays blocked until you answer. No answer within 2 minutes: No, not accepted." }
    $foot.ForeColor = [System.Drawing.Color]::Gray; $foot.Font = New-Object System.Drawing.Font("Segoe UI", 8.5)
    $foot.SetBounds(20, $y, 580, 20); $f.Controls.Add($foot)
    $f.ClientSize = New-Object System.Drawing.Size(620, ($y + 30))

    if ($Demo) {
        $f.Show(); [System.Windows.Forms.Application]::DoEvents()
        $bmp = New-Object System.Drawing.Bitmap($f.Width, $f.Height)
        $f.DrawToBitmap($bmp, (New-Object System.Drawing.Rectangle(0, 0, $f.Width, $f.Height)))
        $bmp.Save($DemoPng, [System.Drawing.Imaging.ImageFormat]::Png); $f.Close(); return
    }
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 120000; $timer.Add_Tick({ $script:answer = "no"; $f.Close() }); $timer.Start()
    $f.Add_Shown({ $f.Activate(); [System.Media.SystemSounds]::Exclamation.Play() })
    [void]$f.ShowDialog(); $timer.Stop(); $f.Dispose()
    return $script:answer
}

# ---------------------------------------------------------------- firewall rules (mode A)
$script:TempOk = @{}      # ip -> expiry ("Accept only now": 10 minutes)
$script:Learned = @{}     # ip -> host, for sites you accepted always

function Get-AllowedRanges {
    $list = New-Object System.Collections.Generic.List[string]
    $AlwaysOk | ForEach-Object { $list.Add($_) }
    foreach ($e in Read-List "allowed.txt") {
        if ([QS.N]::IsIp($e) -or $e.Contains("/")) { $list.Add($e); continue }
        if ($e.StartsWith("*.")) { continue }      # wildcard: learned when the name is seen in the DNS cache
        try { [System.Net.Dns]::GetHostAddresses($e) | ForEach-Object { $list.Add($_.IPAddressToString) } } catch { }
    }
    $blocked = Read-List "blocked.txt"
    foreach ($ip in @($script:Learned.Keys)) { if (-not (Test-Listed $blocked $script:Learned[$ip] $ip)) { $list.Add($ip) } }
    foreach ($ip in @($script:TempOk.Keys)) { if ($script:TempOk[$ip] -gt (Get-Date)) { $list.Add($ip) } else { $script:TempOk.Remove($ip) } }
    # blocked lists win over everything
    return @($list | Select-Object -Unique | Where-Object { -not ([QS.N]::IsIp($_) -and (Test-Listed $blocked $null $_)) })
}

function Update-GuardRules {
    $programs = @(Read-List "programs.txt" | Where-Object { Test-Path -LiteralPath $_ })
    $block = [QS.N]::Complement([string[]](Get-AllowedRanges))
    $existing = @{}
    Get-NetFirewallRule -Group $GuardGroup -ErrorAction SilentlyContinue | ForEach-Object {
        $existing[(($_ | Get-NetFirewallApplicationFilter).Program).ToLower()] = $_
    }
    foreach ($p in $programs) {
        $key = $p.ToLower()
        if ($existing.ContainsKey($key)) {
            Set-NetFirewallRule -Name $existing[$key].Name -RemoteAddress $block
            $existing.Remove($key)
        } else {
            New-NetFirewallRule -DisplayName "Qwen Shield Guard - $(Split-Path -Leaf $p)" -Group $GuardGroup -Program $p `
                -Direction Outbound -Action Block -Profile Any -RemoteAddress $block `
                -Description "$(T 'Chiede prima di lasciar uscire questa AI su internet.' 'Asks before this AI goes on the internet.') $Repo" | Out-Null
        }
    }
    foreach ($r in $existing.Values) { Remove-NetFirewallRule -Name $r.Name }
}

# ---------------------------------------------------------------- the guard (runs in the background)
function Invoke-Decision($answer, $hostName, $ip, $who) {
    $site = if ($hostName) { $hostName } else { $ip }
    switch ($answer) {
        "once"   { $script:TempOk[$ip] = (Get-Date).AddMinutes(10) }
        "always" { Add-ToList "allowed.txt" $site; $script:Learned[$ip] = $site }
        "never"  { Add-ToList "blocked.txt" $site; if ($hostName) { Set-GuardHosts } }
        default  { $script:Cool[$site] = (Get-Date).AddMinutes(2) }
    }
    Write-Log "$($answer.ToUpper().PadRight(6)) $who -> $site ($ip)"
}

function Start-Guard {
    $mutex = New-Object System.Threading.Mutex($false, "Global\QwenPhoneHomeShieldGuard")
    if (-not $mutex.WaitOne(0)) { return }
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    $mode = Get-Mode
    $script:Cool = @{}
    $tray = New-Object System.Windows.Forms.NotifyIcon
    $tray.Icon = [System.Drawing.SystemIcons]::Shield; $tray.Visible = $true
    $tray.Text = "Qwen Phone-Home Shield - $(T 'guardiano attivo' 'guard active') ($mode)"
    $menu = New-Object System.Windows.Forms.ContextMenu
    [void]$menu.MenuItems.Add((T "Gestisci liste e programmi" "Manage lists and programs"), {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Data\QwenShield.ps1`" -Action Manage" })
    [void]$menu.MenuItems.Add((T "Apri registro" "Open log"), { Start-Process notepad.exe (Join-Path $Data "log.txt") })
    $tray.ContextMenu = $menu
    Write-Log "GUARD  start, mode $mode"

    $stamp = { (Get-ChildItem -LiteralPath $Data -Filter *.txt | Where-Object Name -ne "log.txt" | ForEach-Object { $_.LastWriteTimeUtc.Ticks }) -join "," }
    $lastStamp = & $stamp
    $lastRefresh = Get-Date
    $programs = @{}
    $loadPrograms = { $h = @{}; Read-List "programs.txt" | ForEach-Object { $h[$_.ToLower()] = $_ }; $h }
    $programs = & $loadPrograms
    $lastRecord = 0
    if ($mode -eq "A") {
        Update-GuardRules
        $e = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($e) { $lastRecord = $e.RecordId }
    }
    $seen = @{}; $pids = @{}; $lastPids = [datetime]::MinValue

    while ($true) {
      try {
        for ($i = 0; $i -lt 5; $i++) { [System.Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 100 }
        if (Test-Path (Join-Path $Data "stop")) {
            Remove-Item -LiteralPath (Join-Path $Data "stop") -Force; $tray.Visible = $false; $tray.Dispose(); Write-Log "GUARD  stop"; break
        }
        $now = Get-Date
        $s = & $stamp
        if ($s -ne $lastStamp -or ($now - $lastRefresh).TotalMinutes -ge 10 -or @($script:TempOk.Values | Where-Object { $_ -lt $now }).Count) {
            $lastStamp = $s; $lastRefresh = $now; $programs = & $loadPrograms; $seen = @{}
            if ($mode -eq "A") { try { Update-GuardRules } catch { Write-Log "ERROR  rules: $_" } }
        }
        $events = @()
        if ($mode -eq "A") {
            # connections stopped by the firewall rule, read from the Windows security log
            $xp = "*[System[(EventID=5157) and (EventRecordID>$lastRecord)]]"
            $events = @(Get-WinEvent -LogName Security -FilterXPath $xp -MaxEvents 200 -ErrorAction SilentlyContinue | Sort-Object RecordId)
            foreach ($ev in $events) {
                $lastRecord = [Math]::Max($lastRecord, $ev.RecordId)
                $d = @{}; ([xml]$ev.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
                if ($d["Direction"] -ne "%%14593") { continue }
                $path = [QS.N]::DosPath($d["Application"])
                if (-not $programs.ContainsKey($path.ToLower())) { continue }
                Test-Attempt $d["ProcessID"] $programs[$path.ToLower()] $d["DestAddress"] ([int]$d["DestPort"]) $null
            }
        }
        # connections of the guarded programs: mode B cuts the new ones at once, mode A only tells you where they go
        if ($true) {
            if (($now - $lastPids).TotalSeconds -ge 2) {
                $pids = @{}; $lastPids = $now
                Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $programs.ContainsKey($_.Path.ToLower()) } |
                    ForEach-Object { $pids[[int]$_.Id] = $_.Path }
            }
            if ($pids.Count) {
                Get-NetTCPConnection -State Established, SynSent -ErrorAction SilentlyContinue |
                    Where-Object { $pids.ContainsKey([int]$_.OwningProcess) } | ForEach-Object {
                        $key = "$($_.OwningProcess)|$($_.RemoteAddress)"
                        if (-not $seen.ContainsKey($key)) {
                            if ($mode -eq "A") { Show-Connected $_.OwningProcess $pids[[int]$_.OwningProcess] $_.RemoteAddress; $seen[$key] = 1 }
                            elseif (Test-Attempt $_.OwningProcess $pids[[int]$_.OwningProcess] $_.RemoteAddress $_.RemotePort $_) { $seen[$key] = 1 }
                        }
                    }
            }
        }
      } catch { Write-Log "ERROR  $_"; Start-Sleep -Seconds 2 }
    }
}

function Show-Connected($procId, $program, $ip) {
    # you always know where your AI goes: one notice per site every 30 minutes, every connection in the log
    foreach ($r in $AlwaysOk) { if ([QS.N]::InRange($ip, $r)) { return } }
    if ($ip -in @("0.0.0.0", "::")) { return }
    $hostName = Get-HostForIp $ip
    $site = if ($hostName) { $hostName } else { $ip }
    if ($script:Cool.ContainsKey("conn|$site") -and $script:Cool["conn|$site"] -gt (Get-Date)) { return }
    $script:Cool["conn|$site"] = (Get-Date).AddMinutes(30)
    $model = Get-ModelName $procId
    $who = if ($model) { $model } else { Split-Path -Leaf $program }
    Write-Log "CONN   $(Split-Path -Leaf $program) [$model] -> $site ($ip)"
    $tray.ShowBalloonTip(6000, "Qwen Phone-Home Shield", "$who $(T 'è collegato a' 'is connected to') $site", "Info")
}

# returns $true when the destination is allowed (mode B: no need to look at it again)
function Test-Attempt($procId, $program, $ip, $port, $conn) {
    if ($ip -in @("0.0.0.0", "::")) { return $true }     # a sinkholed name: already blocked
    foreach ($r in $AlwaysOk) { if ([QS.N]::InRange($ip, $r)) { return $true } }
    $hostName = Get-HostForIp $ip
    $site = if ($hostName) { $hostName } else { $ip }
    $exe = Split-Path -Leaf $program
    $v6 = $conn -and $conn.LocalAddress -match ":"
    $cut = {
        if ($conn -and -not $v6) {
            [void][QS.N]::KillTcp($conn.LocalAddress, $conn.LocalPort, $conn.RemoteAddress, $conn.RemotePort)
        } elseif ($conn) {
            # an IPv6 connection cannot be cut from outside: the program is closed so no data leaves
            Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
            Write-Log "CLOSE  $exe (IPv6 -> $site)"
        }
    }
    $knownBad = ($ip -in $MetadataIPs) -or ($hostName -and ($Hosts -contains $hostName))
    if ($knownBad -or (Test-Listed (Read-List "blocked.txt") $hostName $ip)) {
        & $cut
        if (-not $script:Cool.ContainsKey("bad|$site") -or $script:Cool["bad|$site"] -lt (Get-Date)) {
            $script:Cool["bad|$site"] = (Get-Date).AddMinutes(10)
            Write-Log "BLOCK  $exe -> $site ($ip)$(if ($knownBad) { ' [Qwen3.8 incident]' })"
            if ($knownBad) { $tray.ShowBalloonTip(8000, "Qwen Phone-Home Shield", "$(T 'Bloccato' 'Blocked'): $exe -> $site", "Warning") }
        }
        return $false
    }
    if ($script:TempOk.ContainsKey($ip) -and $script:TempOk[$ip] -gt (Get-Date)) { if ($conn) { Show-Connected $procId $program $ip }; return $true }
    if (Test-Listed (Read-List "allowed.txt") $hostName $ip) {
        if (-not $script:Learned.ContainsKey($ip)) {
            $script:Learned[$ip] = $site
            if ($mode -eq "A") { Update-GuardRules }
        }
        if ($conn) { Show-Connected $procId $program $ip }
        return $true
    }
    if ($script:Cool.ContainsKey($site) -and $script:Cool[$site] -gt (Get-Date)) { & $cut; return $false }
    $script:Cool[$site] = (Get-Date).AddMinutes(2)      # one question at a time for the same site
    $model = Get-ModelName $procId
    if ($v6) { [QS.N]::Pause([int]$procId, $true) } else { & $cut }
    try { $answer = Show-Ask $model $program $hostName $ip $port -Paused:$v6 }
    finally { if ($v6) { try { [QS.N]::Pause([int]$procId, $false) } catch { } } }
    if ($v6 -and $answer -notin @("once", "always")) { & $cut }
    Invoke-Decision $answer $hostName $ip $exe
    if ($answer -in @("once", "always")) { $script:Cool.Remove($site); if ($mode -eq "A") { Update-GuardRules }; return $true }
    return $false
}

# ---------------------------------------------------------------- manage window
function Show-Manage {
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $f = New-Object System.Windows.Forms.Form
    $f.Text = "Qwen Phone-Home Shield - $(T 'gestione' 'settings')"; $f.StartPosition = "CenterScreen"
    $f.Font = New-Object System.Drawing.Font("Segoe UI", 10); $f.ClientSize = New-Object System.Drawing.Size(720, 470)
    $f.Icon = [System.Drawing.SystemIcons]::Shield; $f.BackColor = [System.Drawing.Color]::White
    $other = Get-OtherFirewall
    $info = New-Object System.Windows.Forms.Label
    $info.Text = if ($other) { T "Modalità B: firewall $other. Le connessioni nuove vengono tagliate subito e ti viene chiesto." "Mode B: firewall $other. New connections are cut at once and you are asked." } `
                 else { T "Modalità A: firewall di Windows. Niente esce finché non accetti." "Mode A: Windows Firewall. Nothing leaves until you accept." }
    $info.SetBounds(16, 12, 690, 40); $f.Controls.Add($info)
    $lbl = New-Object System.Windows.Forms.Label; $lbl.Text = (T "Programmi AI sorvegliati:" "Guarded AI programs:"); $lbl.SetBounds(16, 56, 400, 22); $f.Controls.Add($lbl)
    $list = New-Object System.Windows.Forms.ListBox; $list.SetBounds(16, 80, 688, 250); $list.HorizontalScrollbar = $true; $f.Controls.Add($list)
    $reload = { $list.Items.Clear(); Read-List "programs.txt" | ForEach-Object { [void]$list.Items.Add($_) } }
    & $reload
    $save = { (@(Get-Content -LiteralPath (Join-Path $Data "programs.txt") -Encoding UTF8 | Where-Object { $_.StartsWith("#") }) + @($list.Items)) |
              Set-Content -LiteralPath (Join-Path $Data "programs.txt") -Encoding UTF8 }
    $mk = { param($text, $x, $y, $w, $act) $b = New-Object System.Windows.Forms.Button; $b.Text = $text; $b.SetBounds($x, $y, $w, 36); $b.Add_Click($act); $f.Controls.Add($b) }
    & $mk (T "Aggiungi programma..." "Add program...") 16 340 220 {
        $o = New-Object System.Windows.Forms.OpenFileDialog; $o.Filter = "exe|*.exe"
        if ($o.ShowDialog() -eq "OK" -and -not $list.Items.Contains($o.FileName)) { [void]$list.Items.Add($o.FileName); & $save }
    }
    & $mk (T "Togli selezionato" "Remove selected") 246 340 200 { if ($list.SelectedItem) { $list.Items.Remove($list.SelectedItem); & $save } }
    & $mk (T "Cerca programmi AI" "Find AI programs") 456 340 248 {
        $f.Cursor = "WaitCursor"; Add-FoundPrograms (Find-AiFiles).Exe; & $reload; $f.Cursor = "Default" }
    & $mk (T "Siti autorizzati" "Allowed sites") 16 392 220 { Start-Process notepad.exe (Join-Path $Data "allowed.txt") }
    & $mk (T "Siti bloccati" "Blocked sites") 246 392 200 { Start-Process notepad.exe (Join-Path $Data "blocked.txt") }
    & $mk (T "Registro" "Log") 456 392 248 { Start-Process notepad.exe (Join-Path $Data "log.txt") }
    [void]$f.ShowDialog()
}

# ---------------------------------------------------------------- scan (models + AI programs)
function Find-AiFiles {
    $roots = if ($NoDriveScan) {
        @("$env:USERPROFILE", "$env:LOCALAPPDATA\Programs", "$env:ProgramFiles") | Where-Object { Test-Path $_ }
    } else { Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object { $_.DeviceID + "\" } }
    Say "      $(T 'cerco modelli (.gguf) e programmi AI in' 'looking for models (.gguf) and AI programs in') $($roots -join ' ') ..."
    $all = [QS.N]::Find([string[]]$roots, [string[]]$AiExe, ".gguf")
    [pscustomobject]@{
        Gguf = @($all | Where-Object { $_ -like "*.gguf" })
        Exe  = @($all | Where-Object { $_ -like "*.exe" })
    }
}

function Add-FoundPrograms($exes) {
    foreach ($e in $exes) { Add-ToList "programs.txt" $e }
}

function Test-GgufIsQwen38($path) {
    if ($path -match $ModelPattern) { return $true }
    try {
        $fs = [System.IO.File]::OpenRead($path)
        try { $buf = New-Object byte[] ([Math]::Min(4MB, $fs.Length)); [void]$fs.Read($buf, 0, $buf.Length) } finally { $fs.Close() }
        return $Latin1.GetString($buf) -match "general\.(base)?name.{0,24}$ModelPattern"
    } catch { return $false }
}

function Show-Scan($found) {
    Say "`n[scan] $(T 'modelli Qwen3.8 su questo PC' 'Qwen3.8 models on this PC')" Cyan
    if (-not $found) { $found = Find-AiFiles }
    $models = New-Object System.Collections.Generic.List[string]
    foreach ($o in @($env:OLLAMA_MODELS, "$env:USERPROFILE\.ollama\models") | Where-Object { $_ -and (Test-Path "$_\manifests") }) {
        Get-ChildItem -LiteralPath "$o\manifests" -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match $ModelPattern } |
            ForEach-Object { $models.Add("Ollama     $($_.Directory.Name):$($_.Name)") }
    }
    foreach ($h in @($(if ($env:HF_HOME) { "$env:HF_HOME\hub" }), $env:HF_HUB_CACHE, "$env:USERPROFILE\.cache\huggingface\hub") | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique) {
        Get-ChildItem -LiteralPath $h -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $ModelPattern } | ForEach-Object { $models.Add("HF cache   $($_.FullName)") }
    }
    $found.Gguf | Where-Object { Test-GgufIsQwen38 $_ } | ForEach-Object { $models.Add("GGUF       $_") }
    $report = New-Object System.Collections.Generic.List[string]
    $report.Add("Qwen Phone-Home Shield v$Version - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"); $report.Add("")
    if ($models.Count -eq 0) { Say "      $(T 'nessun modello Qwen3.8' 'no Qwen3.8 model found')" Green; $report.Add((T "Nessun modello Qwen3.8." "No Qwen3.8 model found.")) }
    else {
        Say "      $(T 'trovati' 'found') $($models.Count):" Yellow
        $models | ForEach-Object { Say "        $_" Yellow; $report.Add($_) }
        $report.Add("")
        $report.Add((T "Puoi tenerli e usarli per chat, scrittura, immagini. Il rischio c'è solo quando l'AI può AGIRE (comandi, codice, web): lì il guardiano ti chiede prima." `
                       "You can keep them for chat, writing, vision. The risk is only when the AI can ACT (commands, code, web): there the guard asks you first."))
    }
    if ($found.Exe.Count) { $report.Add(""); $report.Add((T "Programmi AI sorvegliati:" "Guarded AI programs:")); $found.Exe | ForEach-Object { $report.Add("  $_") } }
    $desk = [Environment]::GetFolderPath("Desktop")
    $out = Join-Path $(if ($desk -and (Test-Path $desk)) { $desk } else { $ScriptDir }) "QwenShield-report.txt"
    $report | Set-Content -LiteralPath $out -Encoding UTF8
    Say "      $(T 'resoconto' 'report'): $out"
}

# ---------------------------------------------------------------- enable / disable
function Install-Shield {
    Say "`n[1/4] $(T 'host noti dell''incidente nel file hosts' 'known incident hosts in the hosts file')" Cyan
    if ((Test-Path $HostsPath) -and -not (Test-Path "$HostsPath.qwenshield.bak")) { Copy-Item -LiteralPath $HostsPath -Destination "$HostsPath.qwenshield.bak" }
    $block = @($Start, "# Qwen3.8 phone-home incident (Oct 2026) - v$Version - $Repo") + ($Hosts | ForEach-Object { "0.0.0.0 $_" }) + $End
    Write-HostsText ((Remove-Block (Read-HostsText)) + "`r`n" + ($block -join "`r`n") + "`r`n")
    Clear-Dns
    Say "      $($Hosts.Count) $(T 'host bloccati' 'hosts blocked')" Green

    $other = Get-OtherFirewall
    Say "`n[2/4] $(T 'indirizzi metadata cloud' 'cloud-metadata addresses') $($MetadataIPs -join ', ')" Cyan
    if ($NoFirewall) { Say "      skipped (-NoFirewall)" Yellow }
    elseif (Test-CloudOrVM) { Say "      $(T 'saltato: macchina virtuale/cloud, li usa' 'skipped: virtual/cloud machine, it needs them')" Yellow }
    elseif ($other) { Say "      $(T "firewall $other attivo: ci pensa il guardiano (modalità B)" "firewall $other active: the guard takes care of it (mode B)")" Yellow }
    else {
        Get-NetFirewallRule -Group $FwGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -DisplayName "Qwen Shield - block cloud metadata IPs" -Group $FwGroup -Direction Outbound -Action Block `
            -RemoteAddress $MetadataIPs -Profile Any -Description "Qwen3.8 phone-home incident. $Repo" | Out-Null
        Say "      $(T 'regola firewall aggiunta' 'firewall rule added')" Green
    }

    Say "`n[3/4] $(T 'programmi AI e modelli' 'AI programs and models')" Cyan
    Initialize-Data
    $found = Find-AiFiles
    Add-FoundPrograms $found.Exe
    $n = @(Read-List "programs.txt").Count
    Say "      $n $(T 'programmi AI sorvegliati (aggiungi i tuoi agenti da Gestisci-Guardiano.bat)' 'guarded AI programs (add your agents with Manage-Guard.bat)')" Green

    Say "`n[4/4] $(T 'guardiano delle connessioni' 'connection guard')" Cyan
    if ($NoGuard) { Say "      skipped (-NoGuard)" Yellow }
    else {
        if ($PSCommandPath -ne (Join-Path $Data "QwenShield.ps1")) { Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $Data "QwenShield.ps1") -Force }
        if (-not $other) {
            # mode A reads the connections stopped by the firewall from the security log
            $state = Join-Path $Data "audit-before.txt"
            if (-not (Test-Path $state)) { (auditpol /get /subcategory:$WfpAudit /r | Where-Object { $_.Trim() } | Select-Object -Last 1) | Set-Content -LiteralPath $state }
            auditpol /set /subcategory:$WfpAudit /failure:enable | Out-Null
        }
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        $user = (Get-CimInstance Win32_ComputerSystem).UserName
        if (-not $user) { $user = "$env:USERDOMAIN\$env:USERNAME" }
        $act = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Data\QwenShield.ps1`" -Action Watch"
        $trg = New-ScheduledTaskTrigger -AtLogOn -User $user
        $pri = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
        $set = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $TaskName -Action $act -Trigger $trg -Principal $pri -Settings $set `
            -Description "Qwen Phone-Home Shield: $(T 'chiede prima che un''AI locale vada su internet' 'asks before a local AI goes on the internet'). $Repo" | Out-Null
        Start-ScheduledTask -TaskName $TaskName
        Say "      $(T "attivo, modalità" 'active, mode') $(if ($other) { "B ($other)" } else { 'A' }) - $(T "icona con lo scudo vicino all'orologio" 'shield icon next to the clock')" Green
    }
    return $found
}

function Uninstall-Shield {
    Say "`n$(T 'Disattivo Qwen Phone-Home Shield' 'Disabling Qwen Phone-Home Shield')" Cyan
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    if (Test-Path $Data) { Set-Content -LiteralPath (Join-Path $Data "stop") -Value "stop"; Start-Sleep -Seconds 2 }
    Remove-Item -LiteralPath (Join-Path $Data "stop") -Force -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -match "QwenShield\.ps1.*-Action Watch" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Get-NetFirewallRule -Group $FwGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Get-NetFirewallRule -Group $GuardGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    $state = Join-Path $Data "audit-before.txt"
    if (Test-Path $state) {
        $before = (Get-Content -LiteralPath $state) -join ","
        if ($before -notmatch "Failure|Errore|Fehler|chec|Error") { auditpol /set /subcategory:$WfpAudit /failure:disable | Out-Null }
        Remove-Item -LiteralPath $state -Force
    }
    $text = Read-HostsText
    if ($text.Contains($Start) -or $text.Contains($GStart)) { Write-HostsText (Remove-Block (Remove-Block $text) $GStart $GEnd); Clear-Dns }
    Remove-Item -LiteralPath (Join-Path $Data "QwenShield.ps1") -Force -ErrorAction SilentlyContinue
    Say "  $(T 'fatto: hosts, regole firewall, guardiano e registro di Windows come prima.' 'done: hosts, firewall rules, guard and Windows audit setting as before.')" Green
    Say "  $(T 'Le tue liste restano in' 'Your lists stay in') $Data $(T '(per riattivarlo con le stesse scelte).' '(to enable it again with the same choices).')"
}

# ---------------------------------------------------------------- main
if ($Action -eq "Demo") {
    Show-Ask "Qwen3.8-27B-Q5_K_M" "C:\AI\llama.cpp\llama-server.exe" "sanmaohe.oss-cn-beijing.aliyuncs.com" "203.0.113.10" 443 -Demo
    return
}
Say "Qwen Phone-Home Shield v$Version" White
$needAdmin = $Action -in @("Enable", "Disable", "Manage", "Watch") -and $HostsPath -eq "$env:SystemRoot\System32\drivers\etc\hosts"
if ($needAdmin -and -not (Test-Admin)) {
    Say (T "Servono i diritti di amministratore: usa Attiva/Disattiva (doppio clic)." "Administrator rights are needed: use Enable-Shield.bat / Disable-Shield.bat (double click).") Red
    exit 1
}
switch ($Action) {
    "Enable"  { $f = Install-Shield; Show-Scan $f; Say "`n$(T 'Protezione ATTIVA. Si spegne con Disable-Shield.bat.' 'Shield ENABLED. Turn it off with Disable-Shield.bat.')" Green }
    "Disable" { Uninstall-Shield; Say "`n$(T 'Protezione DISATTIVATA.' 'Shield DISABLED.')" Green }
    "Scan"    { Show-Scan }
    "Manage"  { Initialize-Data; Show-Manage }
    "Status"  { Say "$(T 'modalità' 'mode'): $(Get-Mode)  $(Get-OtherFirewall)"; Say "task: $((Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue).State)" }
    "Watch"   { Initialize-Data; Start-Guard }
}
