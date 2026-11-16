# Atomic Red Team (pinned commit) + Invoke-AtomicRedTeam (pinned version).
#
# Defender is turned off by provision/defender.ps1 (it blocks tests by command line);
# the exclusion below still protects the payloads if Defender is ever back on.
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$AtomicsCommit = "a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6"
$ModuleVersion = "2.3.0"
$Root = "C:\AtomicRedTeam"

New-Item -ItemType Directory -Path $Root -Force | Out-Null
Add-MpPreference -ExclusionPath $Root

Write-Host "[atomic] Invoke-AtomicRedTeam $ModuleVersion (PowerShell Gallery)"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue)) {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
}
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name powershell-yaml -Scope AllUsers -Force
Install-Module -Name Invoke-AtomicRedTeam -RequiredVersion $ModuleVersion -Scope AllUsers -Force

if (-not (Test-Path "$Root\atomics\Indexes")) {
    Write-Host "[atomic] atomics folder at commit $AtomicsCommit"
    $zip = "$env:TEMP\atomics.zip"
    Invoke-WebRequest "https://github.com/redcanaryco/atomic-red-team/archive/$AtomicsCommit.zip" -OutFile $zip
    Expand-Archive $zip -DestinationPath "$env:TEMP\art" -Force
    Move-Item "$env:TEMP\art\atomic-red-team-$AtomicsCommit\atomics" "$Root\atomics" -Force
    Remove-Item $zip, "$env:TEMP\art" -Recurse -Force
}

# Default parameters for every session (used by the capture script).
$profileLine = "Import-Module Invoke-AtomicRedTeam; `$PSDefaultParameterValues = @{'Invoke-AtomicTest:PathToAtomicsFolder' = '$Root\atomics'}"
Set-Content -Path $PROFILE.AllUsersAllHosts -Value $profileLine -Force
Write-Host "[atomic] ready: $((Get-ChildItem "$Root\atomics" -Directory -Filter 'T*').Count) techniques available"
