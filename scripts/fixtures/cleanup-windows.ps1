<#
.SYNOPSIS
    Removes all benign test fixtures planted by plant-windows.ps1.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'SilentlyContinue'
$fixtureDir = Join-Path $env:APPDATA 'fcsweep-fixture-test'
$progDataDir = Join-Path $env:ProgramData 'fcsweep-fixture-test'

Remove-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'FcSweepFixtureRun' -Force
Unregister-ScheduledTask -TaskName 'FcSweepFixtureHiddenTask' -Confirm:$false

Remove-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist' -Name '99' -Force
Remove-Item -Path 'HKCU:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist' -Force
Remove-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Google\Chrome' -Name 'HomepageLocation' -Force

Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' -Name 'z' -Force

$hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
if (Test-Path $hostsPath) {
    $lines = Get-Content $hostsPath | Where-Object { $_ -notmatch '# fcsweep-fixture' -and $_ -notmatch 'fcsweep-fixture-\d\.invalid' }
    Set-Content -Path $hostsPath -Value $lines -Encoding ASCII
}

try { Remove-MpPreference -ExclusionPath $fixtureDir } catch {}

Get-ChildItem 'Cert:\LocalMachine\Root' | Where-Object { $_.Subject -like '*FcSweepFixtureTestRootCA*' } | Remove-Item -Force
Get-ChildItem 'Cert:\CurrentUser\Root' | Where-Object { $_.Subject -like '*FcSweepFixtureTestRootCA*' } | Remove-Item -Force

Remove-Item -Path $fixtureDir -Recurse -Force
Remove-Item -Path $progDataDir -Recurse -Force

Write-Host "Cleaned up all fcsweep Windows fixtures."
