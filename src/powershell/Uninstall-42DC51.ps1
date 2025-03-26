#Requires -Version 7.0

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [SecureString]$LocalAdminPassword,

    [Parameter(Mandatory=$false)]
    [switch]$LastDomainControllerInDomain = $false,

    [Parameter(Mandatory=$false)]
    [switch]$RemoveDnsDelegation = $false,

    [Parameter(Mandatory=$false)]
    [switch]$IgnoreLastDnsServerForZone = $false,

    [Parameter(Mandatory=$false)]
    [switch]$DemoteOperationMasterRole = $false,

    [Parameter(Mandatory=$false)]
    [switch]$NoRebootOnCompletion = $false
)

<#

# Windows PowerShell script for AD DS Deployment
#

Import-Module ADDSDeployment
Uninstall-ADDSDomainController `
-DemoteOperationMasterRole:$true `
-ForceRemoval:$true `
-Force:$true



#>

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires administrative privileges. Please run as Administrator."
    exit 1
}

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Warning "This script requires PowerShell 7 or higher. Current version: $($PSVersionTable.PSVersion)"
    exit 1
}

$global:logDir = "C:\gh\setupdc2k5\logs"
$global:logFile = Join-Path $logDir "dc-demotion-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

function Write-Log {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    Write-Host $logMessage
    Add-Content -Path $global:logFile -Value $logMessage
}

function Test-PendingReboot {
    $rebootPending = $false
    $reasons = @()

    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
        $rebootPending = $true
        $reasons += "Component Based Servicing"
    }

    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
        $rebootPending = $true
        $reasons += "Windows Update"
    }

    $pendingRename = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
    if ($pendingRename.PendingFileRenameOperations) {
        $rebootPending = $true
        $reasons += "Pending File Rename"
    }

    $computerName = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" -Name "ComputerName" -ErrorAction SilentlyContinue
    $pendingComputerName = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName" -Name "ComputerName" -ErrorAction SilentlyContinue
    if ($computerName.ComputerName -ne $pendingComputerName.ComputerName) {
        $rebootPending = $true
        $reasons += "Computer Name Change"
    }

    if ($rebootPending) {
        Write-Log "⚠️ Pending reboot for: $($reasons -join ', ')"
    }

    return $rebootPending
}

function Get-EventLogErrors {
    param (
        [string]$LogName
    )
    try {
        $events = Get-WinEvent -LogName $LogName -ErrorAction Stop | Where-Object {
            $_.LevelDisplayName -in @("Error", "Warning")
        } | Sort-Object TimeCreated -Descending | Select-Object -First 10

        foreach ($event in $events) {
            Write-Log "Event ID: $($event.Id)"
            Write-Log "Level: $($event.LevelDisplayName)"
            Write-Log "Time: $($event.TimeCreated)"
            Write-Log "Source: $($event.ProviderName)"
            Write-Log "Message: $($event.Message)"
            Write-Log "------------------------"
        }
    } catch {
        Write-Log "ERROR: Failed to retrieve $LogName logs. $_"
    }
}

try {
    Write-Log "🚀 Starting DC demotion..."
    $system = Get-WmiObject Win32_ComputerSystem
    Write-Log "DomainRole: $($system.DomainRole)"
    Write-Log "Domain: $($system.Domain)"
    Write-Log "ComputerName: $($system.Name)"

    $dns = Get-WindowsFeature -Name DNS
    Write-Log "DNS Installed: $($dns.Installed)"
    $ad = Get-WindowsFeature -Name AD-Domain-Services
    Write-Log "AD-Domain-Services Installed: $($ad.Installed)"

    $adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
    if ($null -eq $adapter) {
        throw "No active network adapter found for DNS config."
    }

    Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses "8.8.8.8", "8.8.4.4"
    ipconfig /flushdns
    Write-Log "DNS updated and flushed."

    $dnsService = Get-Service -Name DNS -ErrorAction SilentlyContinue
    if ($dnsService) {
        Stop-Service -Name DNS -Force
        Write-Log "DNS service stopped."
    }

    Test-NetConnection -ComputerName 8.8.8.8 -WarningAction SilentlyContinue -TimeoutSeconds 3 | ForEach-Object {
        Write-Log "Ping 8.8.8.8: $($_.PingSucceeded)"
    }

    Test-NetConnection -ComputerName google.com -WarningAction SilentlyContinue -TimeoutSeconds 3 | ForEach-Object {
        Write-Log "Ping google.com: $($_.PingSucceeded)"
    }

    if (Test-PendingReboot) {
        Write-Log "❌ Reboot pending. Please reboot and re-run."
        exit 1
    }

    Get-EventLogErrors -LogName "System"
    Get-EventLogErrors -LogName "Directory Service"

    $services = @("NTDS", "Netlogon", "KDC")
    foreach ($svc in $services) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service) {
            Stop-Service -Name $svc -Force
            Write-Log "$svc service stopped."
        }
    }

    Write-Log "Uninstall-ADDSDomainController running..."
    $params = @{
        LocalAdministratorPassword = $LocalAdminPassword
        Force = $true
    }
    if ($LastDomainControllerInDomain) { $params["LastDomainControllerInDomain"] = $true }
    if ($RemoveDnsDelegation) { $params["RemoveDnsDelegation"] = $true }
    if ($IgnoreLastDnsServerForZone) { $params["IgnoreLastDnsServerForZone"] = $true }
    if ($DemoteOperationMasterRole) { $params["DemoteOperationMasterRole"] = $true }
    if ($NoRebootOnCompletion) { $params["NoRebootOnCompletion"] = $true }

    Uninstall-ADDSDomainController @params
    Write-Log "✅ DC demotion triggered. System reboot expected."
}
catch {
    Write-Log "❌ Error occurred: $_"
    exit 1
}
finally {
    Write-Log "Uninstall-42DC.ps1 complete."
}
