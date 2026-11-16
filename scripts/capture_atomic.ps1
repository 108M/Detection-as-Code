<#
.SYNOPSIS
  Run Atomic Red Team test(s) in the lab VM and export the events of that window.

.DESCRIPTION
  Runs inside the VM (normally through `dac lab capture`). Records the start time,
  runs the test, waits for logging to settle, exports every event of the window from
  the channels the rules use, then runs the test's cleanup.

  Output: one flat JSON object per line (same shape as OTRF datasets: EventID,
  Channel, SourceName, Hostname, TimeCreated + event data fields), gzip-compressed,
  so it goes through the same normaliser as the public datasets.

.EXAMPLE
  C:\dac\scripts\capture_atomic.ps1 -Technique T1218.005 -TestNumbers 2 -Name mshta_vbscript_exec
#>
param(
    [Parameter(Mandatory)] [string] $Technique,
    [string] $TestNumbers = "",
    [Parameter(Mandatory)] [string] $Name,
    [string] $OutDir = "C:\dac\tests\datasets\captures",
    [int] $SettleSeconds = 20,
    [switch] $Benign,               # run $Command instead of an Atomic test
    [string] $Command = ""
)
$ErrorActionPreference = "Stop"
$Channels = @(
    "Microsoft-Windows-Sysmon/Operational",
    "Security",
    "System",
    "Microsoft-Windows-PowerShell/Operational",
    "Windows PowerShell",
    "Microsoft-Windows-Windows Defender/Operational"
)

function ConvertTo-FlatEvent([System.Diagnostics.Eventing.Reader.EventRecord] $Record) {
    $xml = [xml] $Record.ToXml()
    $sys = $xml.Event.System
    # <EventID> is plain text, or an element with a Qualifiers attribute.
    $eventId = if ($sys.EventID -is [string]) { $sys.EventID } else { $sys.EventID.'#text' }
    $out = [ordered] @{
        EventID     = [int] $eventId
        Channel     = [string] $sys.Channel
        SourceName  = [string] $sys.Provider.Name
        Hostname    = [string] $sys.Computer
        TimeCreated = $Record.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        RecordId    = $Record.RecordId
    }
    if ($xml.Event.EventData) {
        $i = 0
        foreach ($d in $xml.Event.EventData.Data) {
            $i++
            $key = if ($d.Name) { $d.Name } else { "param$i" }
            $out[$key] = if ($d -is [string]) { $d } else { [string] $d.'#text' }
        }
    }
    if ($xml.Event.UserData) {
        foreach ($container in $xml.Event.UserData.ChildNodes) {
            foreach ($child in $container.ChildNodes) { $out[$child.LocalName] = [string] $child.InnerText }
        }
    }
    return $out
}

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$start = Get-Date
Start-Sleep -Seconds 2

if ($Benign) {
    Write-Host "[capture] benign activity: $Command"
    Invoke-Expression $Command
} else {
    Import-Module Invoke-AtomicRedTeam -ErrorAction Stop
    $common = @{ PathToAtomicsFolder = "C:\AtomicRedTeam\atomics" }
    if ($TestNumbers) { $common.TestNumbers = $TestNumbers -split "," }
    Write-Host "[capture] prerequisites for $Technique $TestNumbers"
    Invoke-AtomicTest $Technique @common -GetPrereqs | Out-Null
    $start = Get-Date
    Start-Sleep -Seconds 2
    Write-Host "[capture] running $Technique $TestNumbers"
    Invoke-AtomicTest $Technique @common -TimeoutSeconds 120 *>&1 | Out-String | Write-Host
}

Write-Host "[capture] waiting $SettleSeconds s for logs to settle"
Start-Sleep -Seconds $SettleSeconds
$end = Get-Date

$events = foreach ($channel in $Channels) {
    try {
        Get-WinEvent -FilterHashtable @{ LogName = $channel; StartTime = $start; EndTime = $end } -ErrorAction Stop
    } catch [Exception] {
        if ($_.Exception.Message -notmatch "No events were found") { Write-Warning "$channel : $_" }
    }
}
# Drop the PowerShell logging produced by the lab plumbing: this capture process
# (loading Invoke-AtomicRedTeam emits thousands of 4103/800 events) and the WinRM
# session host Vagrant uses to start and poll it (wsmprovhost.exe). Atomic tests run
# in child processes, so attacker PowerShell is kept. Caveat: WinRM-based techniques
# executed against this same VM would lose their wsmprovhost logging.
$plumbingPids = @($PID) + @(Get-CimInstance Win32_Process -Filter "Name='wsmprovhost.exe'" |
    ForEach-Object { [int] $_.ProcessId })
$plumbingHostIds = @{ ([string] $Host.InstanceId) = $true }
foreach ($e in $events) {
    if ($e.LogName -eq "Microsoft-Windows-PowerShell/Operational" -and $plumbingPids -contains $e.ProcessId) {
        $m = [regex]::Match([string] $e.Properties[0].Value, "Host ID = ([0-9a-fA-F-]{36})")
        if ($m.Success) { $plumbingHostIds[$m.Groups[1].Value] = $true }
    }
}
function Test-PlumbingEvent([System.Diagnostics.Eventing.Reader.EventRecord] $Record) {
    if ($Record.LogName -eq "Microsoft-Windows-PowerShell/Operational") {
        return $plumbingPids -contains $Record.ProcessId
    }
    if ($Record.LogName -eq "Windows PowerShell") {
        $m = [regex]::Match(($Record.Properties.Value -join "`n"), "HostId=([0-9a-fA-F-]{36})")
        return $m.Success -and $plumbingHostIds.ContainsKey($m.Groups[1].Value)
    }
    return $false
}
$all = @($events)
$events = $all | Where-Object { -not (Test-PlumbingEvent $_) } | Sort-Object TimeCreated
$dropped = $all.Count - @($events).Count
Write-Host "[capture] dropped $dropped PowerShell events from the lab plumbing (capture process, WinRM host)"

$file = Join-Path $OutDir "$Name.json.gz"
$stream = [IO.File]::Create($file)
$gzip = New-Object IO.Compression.GZipStream($stream, [IO.Compression.CompressionLevel]::Optimal)
$writer = New-Object IO.StreamWriter($gzip, (New-Object Text.UTF8Encoding $false))
$writer.NewLine = "`n"
$count = 0
foreach ($e in $events) {
    $writer.WriteLine((ConvertTo-FlatEvent $e | ConvertTo-Json -Compress -Depth 3))
    $count++
}
$writer.Dispose(); $gzip.Dispose(); $stream.Dispose()

if (-not $Benign) {
    Write-Host "[capture] cleanup"
    Invoke-AtomicTest $Technique @common -Cleanup *>&1 | Out-Null
}

$hash = (Get-FileHash $file -Algorithm SHA256).Hash.ToLower()
$meta = [ordered] @{
    name = $Name; technique = $Technique; tests = $TestNumbers; events = $count; dropped_plumbing_events = $dropped
    start = $start.ToUniversalTime().ToString("o"); end = $end.ToUniversalTime().ToString("o")
    host = $env:COMPUTERNAME; os = (Get-CimInstance Win32_OperatingSystem).Caption
    sysmon = (Get-Item "C:\ProgramData\dac\sysmon\Sysmon64.exe").VersionInfo.FileVersion
    sha256 = $hash
}
$meta | ConvertTo-Json | Set-Content -Path (Join-Path $OutDir "$Name.meta.json") -Encoding utf8
Write-Host "[capture] $count events -> $file"
Write-Host "DAC_CAPTURE_RESULT $($meta | ConvertTo-Json -Compress)"
