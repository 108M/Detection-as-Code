# Sysmon with Olaf Hartong's sysmon-modular config (pinned release + sha256).
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$ConfigRelease = "configs-a45dedb13a43"
$ConfigSha256  = "64bec37ba849c5f2934a55d2a29e7ddfae46a30d56f7f2908d1f8a454898797e"
$Work = "C:\ProgramData\dac\sysmon"
New-Item -ItemType Directory -Path $Work -Force | Out-Null

Write-Host "[sysmon] downloading Sysmon (Sysinternals)"
Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$Work\Sysmon.zip"
Expand-Archive "$Work\Sysmon.zip" -DestinationPath $Work -Force
$sig = Get-AuthenticodeSignature "$Work\Sysmon64.exe"
if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "Microsoft") {
    throw "Sysmon64.exe signature is not a valid Microsoft signature: $($sig.Status)"
}

Write-Host "[sysmon] downloading sysmon-modular config $ConfigRelease"
$cfg = "$Work\sysmonconfig.xml"
Invoke-WebRequest "https://github.com/olafhartong/sysmon-modular/releases/download/$ConfigRelease/sysmonconfig.xml" -OutFile $cfg
$hash = (Get-FileHash $cfg -Algorithm SHA256).Hash.ToLower()
if ($hash -ne $ConfigSha256) { throw "sysmon config sha256 mismatch: $hash" }

if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
    Write-Host "[sysmon] already installed: updating config"
    & "$Work\Sysmon64.exe" -c $cfg | Out-Null
} else {
    Write-Host "[sysmon] installing"
    & "$Work\Sysmon64.exe" -accepteula -i $cfg | Out-Null
}
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:536870912 | Out-Null
$v = (Get-Item "$Work\Sysmon64.exe").VersionInfo.FileVersion
Write-Host "[sysmon] running Sysmon $v with $ConfigRelease"
