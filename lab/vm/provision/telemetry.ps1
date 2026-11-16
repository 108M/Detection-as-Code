# Native Windows telemetry used by the rules: process creation with command line
# (Security 4688), PowerShell script block / module logging (4104/4103) and bigger
# event logs so a capture window is never rotated away.
$ErrorActionPreference = "Stop"

Write-Host "[telemetry] audit policy: process creation, logon, services, log clearing"
$subcategories = @(
    "Process Creation", "Process Termination", "Logon", "Special Logon",
    "Security System Extension", "Security State Change", "Other Object Access Events",
    "User Account Management", "Security Group Management", "Audit Policy Change"
)
foreach ($s in $subcategories) {
    auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null
}

Write-Host "[telemetry] include command line in 4688"
$audit = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item -Path $audit -Force | Out-Null
Set-ItemProperty -Path $audit -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord

Write-Host "[telemetry] PowerShell script block and module logging"
$ps = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
New-Item -Path "$ps\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty -Path "$ps\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -Type DWord
New-Item -Path "$ps\ModuleLogging\ModuleNames" -Force | Out-Null
Set-ItemProperty -Path "$ps\ModuleLogging" -Name EnableModuleLogging -Value 1 -Type DWord
Set-ItemProperty -Path "$ps\ModuleLogging\ModuleNames" -Name "*" -Value "*"

Write-Host "[telemetry] event log sizes"
foreach ($log in "Security", "System", "Microsoft-Windows-PowerShell/Operational") {
    wevtutil sl $log /ms:268435456 | Out-Null
}
Write-Host "[telemetry] done"
