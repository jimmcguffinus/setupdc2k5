# Uninstall-42DC.ps1
# Purpose: Safely uninstall a domain controller with enhanced debugging and cleanup
# Author: Your Name
# Date: 2025-03-21
# Version: 1.0

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
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

# Check if we need to use Windows PowerShell
$useWinPS = $false
if ($PSVersionTable.PSVersion.Major -ge 7) {
    Write-Host "PowerShell 7+ detected. Some commands will use Windows PowerShell compatibility."
    $useWinPS = $true
}

# Function to run command in Windows PowerShell if needed
function Invoke-WinPSCommand {
    param(
        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock
    )
    
    if ($useWinPS) {
        $result = powershell.exe -Command $ScriptBlock
        return $result
    } else {
        return & $ScriptBlock
    }
}

# Import required modules
try {
    # Create Windows PowerShell compatibility session
    if (-not (Get-Module -Name PSCompatSession -ErrorAction SilentlyContinue)) {
        $session = New-PSSession -UseWindowsPowerShell
        Import-Module -Name ServerManager, ActiveDirectory -PSSession $session -SkipEditionCheck -ErrorAction Stop
    }
}
catch {
    Write-Warning "Failed to import required modules: $_"
    exit 1
}

# Ensure running with administrative privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Warning "This script requires administrative privileges. Please run as Administrator."
    exit 1
}

# Ensure running on PowerShell 7 or higher
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Warning "This script requires PowerShell 7 or higher. Current version: $($PSVersionTable.PSVersion)"
    exit 1
}

# Setup logging
$global:logDir = "C:\gh\setupdc2k5\logs"
$global:logFile = Join-Path $logDir "dc-demotion-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

# Create log directory if it doesn't exist
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

function Get-EventLogErrors {
    param (
        [string]$LogName,
        [int]$Hours = 24
    )
    
    try {
        # Use Get-WinEvent instead of Get-EventLog
        $events = Get-WinEvent -LogName $LogName -MaxEvents 40 -ErrorAction Stop |
            Where-Object { $_.Level -in @(2,3) } # 2=Error, 3=Warning
        
        foreach ($event in $events) {
            Write-Log "Event ID: $($event.Id)"
            Write-Log "Level: $($event.LevelDisplayName)"
            Write-Log "Time: $($event.TimeCreated)"
            Write-Log "Source: $($event.ProviderName)"
            Write-Log "Message: $($event.Message)"
            Write-Log "------------------------"
        }
    }
    catch {
        Write-Log "ERROR: Failed to get events from $LogName. Error: $_"
    }
}

function Test-PendingReboot {
    $rebootPending = $false
    $reasons = @()

    # Check Component Based Servicing
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
        $rebootPending = $true
        $reasons += "Component Based Servicing"
    }

    # Check Windows Update
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
        $rebootPending = $true
        $reasons += "Windows Update"
    }

    # Check Pending File Rename Operations
    $pendingRename = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
    if ($pendingRename.PendingFileRenameOperations) {
        $rebootPending = $true
        $reasons += "Pending File Rename"
    }

    # Check Computer Name Change
    $computerName = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" -Name "ComputerName" -ErrorAction SilentlyContinue
    $pendingComputerName = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName" -Name "ComputerName" -ErrorAction SilentlyContinue
    if ($computerName.ComputerName -ne $pendingComputerName.ComputerName) {
        $rebootPending = $true
        $reasons += "Computer Name Change"
    }

    if ($rebootPending) {
        Write-Log "⚠️ WARNING: System has pending reboot(s) for: $($reasons -join ', ')"
    }
    return $rebootPending
}

try {
    Write-Log "🚀 Starting DC demotion with enhanced debugging..."
    
    # Log initial system state
    Write-Log "=== Initial System State ==="
    $systemInfo = Get-CimInstance Win32_ComputerSystem
    Write-Log "DomainRole: $($systemInfo.DomainRole)"
    Write-Log "Domain: $($systemInfo.Domain)"
    Write-Log "ComputerName: $($systemInfo.Name)"
    
    # Check AD-Domain-Services and DNS roles using Windows PowerShell
    Write-Log "=== Checking AD DS and DNS Roles ==="
    try {
        $roles = Invoke-WinPSCommand { Get-WindowsFeature -Name AD-Domain-Services,DNS-Server }
        Write-Log "AD-Domain-Services Installed: $(($roles | Where-Object Name -eq 'AD-Domain-Services').Installed)"
        Write-Log "DNS Installed: $(($roles | Where-Object Name -eq 'DNS-Server').Installed)"
    }
    catch {
        Write-Log "WARNING: Could not check Windows Features: $_"
    }
    
    # Log network configuration
    Write-Log "=== Network Configuration ==="
    $ipConfig = ipconfig /all
    Write-Log $ipConfig
    
    # Set public DNS servers
    Write-Log "=== Setting Public DNS Servers ==="
    try {
        $adapter = Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.NetConnectionID -eq "Ethernet" -and $_.PhysicalAdapter -eq $true }
        if ($adapter) {
            $config = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.InterfaceIndex -eq $adapter.InterfaceIndex }
            $config.SetDNSServerSearchOrder(@("8.8.8.8", "8.8.4.4"))
            Write-Log "DNS servers set to 8.8.8.8 and 8.8.4.4."
            ipconfig /flushdns
            Write-Log "DNS cache flushed."
        }
        else {
            Write-Log "WARNING: Could not find network adapter"
        }
    }
    catch {
        Write-Log "WARNING: Failed to set DNS servers: $_"
    }
    
    # Test network connectivity
    Write-Log "=== Testing Network Connectivity ==="
    
    # Test ping to 8.8.8.8 with timeout
    try {
        $pingResult = Test-NetConnection -ComputerName 8.8.8.8 -WarningAction SilentlyContinue -TimeoutSeconds 5
        Write-Log "Ping 8.8.8.8: $($pingResult.PingSucceeded)"
    }
    catch {
        Write-Log "WARNING: Failed to ping 8.8.8.8: $_"
    }
    
    # Test ping to google.com with timeout
    try {
        $pingResult = Test-NetConnection -ComputerName google.com -WarningAction SilentlyContinue -TimeoutSeconds 5
        Write-Log "Ping google.com: $($pingResult.PingSucceeded)"
    }
    catch {
        Write-Log "WARNING: Failed to ping google.com: $_"
    }
    
    # Test DNS resolution with timeout
    try {
        $job = Start-Job -ScriptBlock { nslookup google.com }
        if (Wait-Job $job -Timeout 5) {
            $nslookupResult = Receive-Job $job
            Write-Log "NSLookup google.com: $nslookupResult"
        }
        else {
            Stop-Job $job
            Write-Log "WARNING: DNS lookup timed out after 5 seconds"
        }
    }
    catch {
        Write-Log "WARNING: Failed DNS lookup: $_"
    }
    
    # Check for pending reboot
    Write-Log "=== Checking for Pending Reboot ==="
    $pendingReboot = Test-PendingReboot
    if ($pendingReboot) {
        Write-Log "⚠️ WARNING: System has pending reboot(s). Please reboot before proceeding."
        exit 1
    }
    Write-Log "No pending reboot detected. Proceeding with demotion..."
    
    # Get event log errors
    Write-Log "=== Extracting Warnings and Errors from System Event Log ==="
    Get-EventLogErrors -LogName "System"
    
    Write-Log "=== Extracting Warnings and Errors from Directory Service Event Log ==="
    Get-EventLogErrors -LogName "Directory Service"
    
    # Stop AD DS services
    Write-Log "=== Stopping AD DS Services ==="
    $services = @("NTDS", "Netlogon", "KDC")
    foreach ($service in $services) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc) {
            Write-Log "Service $service status: $($svc.Status)"
            Write-Log "Attempting to stop $service..."
            try {
                Stop-Service -Name $service -Force
                Write-Log "Service $service stopped successfully. New status: $($svc.Status)"
            }
            catch {
                Write-Log "ERROR: Failed to stop $service. Error: $_"
            }
        } else {
            Write-Log "Service $service not found."
        }
    }
    
    # Attempt standard demotion using Windows PowerShell
    Write-Log "=== Attempting Standard Demotion ==="
    Write-Log "Running Uninstall-ADDSDomainController..."
    
    $params = @{
        LocalAdministratorPassword = $LocalAdminPassword
        Force = $true
    }
    
    if ($LastDomainControllerInDomain) {
        $params.Add("LastDomainControllerInDomain", $true)
    }
    if ($RemoveDnsDelegation) {
        $params.Add("RemoveDnsDelegation", $true)
    }
    if ($IgnoreLastDnsServerForZone) {
        $params.Add("IgnoreLastDnsServerForZone", $true)
    }
    if ($DemoteOperationMasterRole) {
        $params.Add("DemoteOperationMasterRole", $true)
    }
    if ($NoRebootOnCompletion) {
        $params.Add("NoRebootOnCompletion", $true)
    }
    
    # Convert params to string for Windows PowerShell
    $paramString = $params.GetEnumerator() | ForEach-Object { 
        if ($_.Value -is [bool]) {
            "-$($_.Key):`$$($_.Value)".ToLower()
        } else {
            "-$($_.Key) $($_.Value)"
        }
    }
    
    $demoteCommand = "Uninstall-ADDSDomainController $($paramString -join ' ')"
    if ($useWinPS) {
        powershell.exe -Command $demoteCommand
    } else {
        Invoke-Expression $demoteCommand
    }
    
    Write-Log "✅ Demotion initiated. System will reboot."
}
catch {
    Write-Log "❌ ERROR: An error occurred during demotion: $_"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)"
    exit 1
}
finally {
    Write-Log "Exiting Uninstall-42DC.ps1..."
} 