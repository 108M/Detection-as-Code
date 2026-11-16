# Turn LSA protection (LSASS as a Protected Process Light) off inside the disposable lab
# VM. Windows 11 22H2+ enables it by default (RunAsPPL = 2, no UEFI lock): credential
# dumping tools then get "access denied" opening lsass.exe, so there is no dump and no
# Sysmon 10 event (Sysmon only logs handles that were granted). With it off, Atomic
# credential-access tests produce the full telemetry the rules are written for.
#
# Takes effect after a reboot (the Vagrantfile sets reboot: true for this provisioner).
# If RunAsPPL was set to 1 with a UEFI lock, the registry alone is not enough: use
# Microsoft's LSAPPLConfig opt-out tool instead.
$ErrorActionPreference = "Stop"

$lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$before = Get-ItemProperty $lsa
Write-Host "[lsa] RunAsPPL=$($before.RunAsPPL) RunAsPPLBoot=$($before.RunAsPPLBoot) -> 0 (reboot required)"
Set-ItemProperty -Path $lsa -Name RunAsPPL -Value 0 -Type DWord
Set-ItemProperty -Path $lsa -Name RunAsPPLBoot -Value 0 -Type DWord
