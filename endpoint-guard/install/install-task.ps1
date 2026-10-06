#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Installs Endpoint Guard so it starts at every user logon.

.DESCRIPTION
  Copies the app to C:\Program Files\EndpointGuard (read-only for standard users),
  places the config in C:\ProgramData\EndpointGuard, and registers a scheduled
  task that runs in each interactive user's session at logon. Low-level keyboard
  and mouse hooks only work inside the user's desktop session, which is why this
  is a logon task rather than a Windows service.

.EXAMPLE
  .\install-task.ps1 -Config ..\config.example.json
  .\install-task.ps1 -Uninstall
#>
param(
    [string]$Config = "$PSScriptRoot\..\config.example.json",
    [string]$Python = (Get-Command pythonw.exe -ErrorAction SilentlyContinue).Source,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$TaskName   = "EndpointGuard"
$AppDir     = "C:\Program Files\EndpointGuard"
$DataDir    = "C:\ProgramData\EndpointGuard"
$ConfigPath = Join-Path $DataDir "config.json"

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -Filter "Name='pythonw.exe'" |
        Where-Object { $_.CommandLine -like "*-m guard*" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
    Remove-Item $AppDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Endpoint Guard removed (logs kept in $DataDir)."
    return
}

if (-not $Python) { throw "pythonw.exe not found; pass -Python 'C:\Path\To\pythonw.exe'" }

# 1. Application files: admins write, users read/execute only.
New-Item -ItemType Directory -Force -Path $AppDir, $DataDir | Out-Null
Copy-Item -Recurse -Force "$PSScriptRoot\..\guard" $AppDir
Copy-Item -Force $Config $ConfigPath

# 2. Users may append to the event log, but may not edit the config.
icacls $DataDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" | Out-Null
$log = (Get-Content $ConfigPath -Raw | ConvertFrom-Json).log_file
if ($log) {
    $logDir = Split-Path $log -Parent
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    icacls $logDir /grant "*S-1-5-32-545:(OI)(CI)(RX,AD,WD)" | Out-Null
}

# 3. Logon task, runs as whichever user logs on (members of BUILTIN\Users).
$action    = New-ScheduledTaskAction -Execute $Python -Argument "-m guard -c `"$ConfigPath`" run --quiet" -WorkingDirectory $AppDir
$trigger   = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545" -RunLevel Limited
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
               -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Force | Out-Null

# 4. Optional: deny deletion inside protected folders.
$protected = (Get-Content $ConfigPath -Raw | ConvertFrom-Json).protected_paths
foreach ($path in $protected) {
    if (Test-Path $path) { icacls $path /deny "*S-1-1-0:(OI)(CI)(DE,DC)" | Out-Null; Write-Host "Delete-protected: $path" }
}

Write-Host "Installed. Endpoint Guard starts at the next logon (or run: Start-ScheduledTask $TaskName)."
