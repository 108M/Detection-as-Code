# Turn Microsoft Defender off inside the disposable lab VM so Atomic tests actually
# execute (with it on, behaviour/AMSI detection kills e.g. `mshta javascript:...` by
# command line, and path exclusions don't help).
#
# Tamper Protection cannot be disabled from a script: switch it off once by hand in
# the VM (Windows Security > Virus & threat protection > Manage settings > Tamper
# Protection), then run `vagrant provision --provision-with defender`.
$ErrorActionPreference = "Stop"

$status = Get-MpComputerStatus
if ($status.IsTamperProtected) {
    Write-Warning "[defender] Tamper Protection is ON: switch it off in Windows Security, then run: vagrant provision --provision-with defender"
    exit 0
}

Write-Host "[defender] disabling real-time, behaviour, IOAV, script scanning and cloud submission"
Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true `
    -DisableIOAVProtection $true -DisableScriptScanning $true -DisableBlockAtFirstSeen $true `
    -MAPSReporting Disabled -SubmitSamplesConsent NeverSend -PUAProtection Disabled

# Policy keys make it survive reboots (honoured once Tamper Protection is off).
$pol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
New-Item -Path "$pol\Real-Time Protection" -Force | Out-Null
Set-ItemProperty -Path $pol -Name DisableAntiSpyware -Value 1 -Type DWord
Set-ItemProperty -Path "$pol\Real-Time Protection" -Name DisableRealtimeMonitoring -Value 1 -Type DWord
Set-ItemProperty -Path "$pol\Real-Time Protection" -Name DisableBehaviorMonitoring -Value 1 -Type DWord
Set-ItemProperty -Path "$pol\Real-Time Protection" -Name DisableScriptScanning -Value 1 -Type DWord

$after = Get-MpComputerStatus
Write-Host "[defender] real-time protection enabled: $($after.RealTimeProtectionEnabled)"
