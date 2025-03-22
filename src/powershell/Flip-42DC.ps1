# Flip-42DC.ps1

# Global variables for logging
$global:logDir = "C:\gh\setupdc2k5\logs"
$global:logFile = Join-Path $logDir "flip-42dc-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

# Ensure log directory exists
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

# Logging function
function Write-Log {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    Write-Output $logMessage
    Add-Content -Path $global:logFile -Value $logMessage
}

# Function to pull warnings and errors from Event Logs
function Get-EventLogErrors {
    param($LogName)
    Write-Log "=== Extracting Warnings and Errors from $LogName Event Log ==="
    try {
        $events = Get-WinEvent -LogName $LogName -ErrorAction Stop | 
            Where-Object { 
                $_.LevelDisplayName -eq "Error" -or $_.LevelDisplayName -eq "Warning" 
            } | 
            Where-Object { $_.TimeCreated -ge (Get-Date).AddHours(-24) } | 
            Sort-Object TimeCreated -Descending | 
            Select-Object -First 10

        if ($events) {
            foreach ($event in $events) {
                Write-Log "Event ID: $($event.Id)"
                Write-Log "Level: $($event.LevelDisplayName)"
                Write-Log "Time: $($event.TimeCreated)"
                Write-Log "Source: $($event.ProviderName)"
                Write-Log "Message: $($event.Message)"
                Write-Log "------------------------"
            }
        }
        else {
            Write-Log "No warnings or errors found in $LogName Event Log (last 24 hours)."
        }
    }
    catch {
        Write-Log "ERROR: Failed to retrieve events from $LogName Event Log. Error: $_"
    }
}

# Function to check system role
function Get-SystemRole {
    $role = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole
    switch ($role) {
        0 { return "Workgroup" }
        1 { return "Workgroup" }
        2 { return "MemberServer" }
        3 { return "MemberServer" }
        4 { return "DomainController" }
        5 { return "DomainController" }
        default { return "Unknown" }
    }
}

# Function to backup Administrator profile
function Backup-42AdminProfile {
    $profilePath = [System.Environment]::GetFolderPath('UserProfile')
    $backupPath = "C:\AdminProfileBackup"
    Write-Log "🔹 Backing up Administrator profile from $profilePath..."
    if (-not (Test-Path $backupPath)) {
        New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
    }
    Copy-Item -Path "$profilePath\*" -Destination $backupPath -Recurse -Force -ErrorAction Stop
    Write-Log "✅ Backup complete."
}

# Function to restore Administrator profile
function Restore-42AdminProfile {
    $profilePath = [System.Environment]::GetFolderPath('UserProfile')
    $backupPath = "C:\AdminProfileBackup"
    Write-Log "🔹 Restoring Administrator profile to $profilePath..."
    if (Test-Path $backupPath) {
        Copy-Item -Path "$backupPath\*" -Destination $profilePath -Recurse -Force -ErrorAction Stop
        Write-Log "✅ Restore complete."
    }
    else {
        Write-Log "❌ Backup not found at $backupPath."
    }
}

# Function to install Domain Controller
function Install-42DomainController {
    param(
        [Parameter(Mandatory)]
        [string]$DomainName,
        [Parameter(Mandatory)]
        [SecureString]$SafeModePassword
    )
    Write-Log "🚀 Promoting to DC for domain $DomainName..."
    Backup-42AdminProfile
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    Install-ADDSDomainController `
        -DomainName $DomainName `
        -SafeModeAdministratorPassword $SafeModePassword `
        -InstallDns:$true `
        -Force:$true
    Write-Log "✅ DC promotion initiated. System will reboot."
}

# Function to uninstall Domain Controller with enhanced debugging
function Uninstall-42DomainController {
    param(
        [Parameter(Mandatory)]
        [SecureString]$LocalAdminPassword
    )
    Write-Log "🚀 Starting DC demotion with enhanced debugging..."

    # Log initial system state
    Write-Log "=== Initial System State ==="
    $system = Get-WmiObject -Class Win32_ComputerSystem
    Write-Log "DomainRole: $($system.DomainRole)"
    Write-Log "Domain: $($system.Domain)"
    Write-Log "ComputerName: $($system.Name)"

    # Log role status
    $addsRole = Get-WindowsFeature -Name AD-Domain-Services
    Write-Log "AD-Domain-Services Installed: $($addsRole.Installed)"
    $dnsRole = Get-WindowsFeature -Name DNS
    Write-Log "DNS Installed: $($dnsRole.Installed)"

    # Log network configuration
    Write-Log "=== Network Configuration ==="
    $ipConfig = ipconfig /all
    Write-Log ($ipConfig | Out-String)

    # Ensure DNS is set to a public server
    Write-Log "=== Setting Public DNS Servers ==="
    try {
        Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses ("8.8.8.8", "8.8.4.4")
        Write-Log "DNS servers set to 8.8.8.8 and 8.8.4.4."
        ipconfig /flushdns
        Write-Log "DNS cache flushed."
    }
    catch {
        Write-Log "ERROR: Failed to set DNS servers. Error: $_"
    }

    # Stop the DNS Server service
    Write-Log "=== Stopping DNS Server Service ==="
    $dnsService = Get-Service -Name DNS -ErrorAction SilentlyContinue
    if ($dnsService) {
        Write-Log "DNS service status: $($dnsService.Status)"
        try {
            Stop-Service -Name DNS -Force -ErrorAction Stop
            Write-Log "DNS service stopped successfully."
        }
        catch {
            Write-Log "ERROR: Failed to stop DNS service. Error: $_"
        }
    }
    else {
        Write-Log "DNS service not found."
    }

    # Test network connectivity
    Write-Log "=== Testing Network Connectivity ==="
    $pingIp = Test-Connection -ComputerName 8.8.8.8 -Count 2 -Quiet
    Write-Log "Ping 8.8.8.8: $pingIp"
    $pingDns = Test-Connection -ComputerName google.com -Count 2 -Quiet
    Write-Log "Ping google.com: $pingDns"
    $nslookup = nslookup google.com 2>&1
    Write-Log "NSLookup google.com: $($nslookup | Out-String)"

    # Check for pending reboot
    Write-Log "=== Checking for Pending Reboot ==="
    $rebootReg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    $updateReg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    $pendingReboot = (Test-Path $rebootReg) -or (Test-Path $updateReg)
    Write-Log "Pending Reboot: $pendingReboot"
    if ($pendingReboot) {
        Write-Log "Pending reboot detected. Rebooting to clear state..."
        Restart-Computer -Force
        return
    }
    else {
        Write-Log "No pending reboot detected. Proceeding with demotion..."
    }

    # Pull initial Event Log errors
    Get-EventLogErrors -LogName "System"
    Get-EventLogErrors -LogName "Directory Service"

    # Stop AD DS services
    Write-Log "=== Stopping AD DS Services ==="
    $services = @("NTDS", "Netlogon", "KDC")
    foreach ($service in $services) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc) {
            Write-Log "Service $service status: $($svc.Status)"
            try {
                Write-Log "Attempting to stop $service..."
                Stop-Service -Name $service -Force -ErrorAction Stop
                $svc.Refresh()
                Write-Log "Service $service stopped successfully. New status: $($svc.Status)"
            }
            catch {
                Write-Log "ERROR: Failed to stop $service. Error: $_"
            }
        }
        else {
            Write-Log "Service $service not found."
        }
    }

    # Pull Event Log errors after stopping services
    Get-EventLogErrors -LogName "System"
    Get-EventLogErrors -LogName "Directory Service"

    # Attempt standard demotion
    Write-Log "=== Attempting Standard Demotion ==="
    try {
        Write-Log "Running Uninstall-ADDSDomainController..."
        Uninstall-ADDSDomainController `
            -LocalAdministratorPassword $LocalAdminPassword `
            -DemoteOperationMasterRole:$true `
            -LastDomainControllerInDomain:$true `
            -RemoveDnsDelegation:$true `
            -RemoveApplicationPartitions:$true `
            -IgnoreLastDnsServerForZone:$true `
            -Force:$true
        Write-Log "✅ Demotion initiated. System will reboot."
        return
    }
    catch {
        Write-Log "ERROR: Standard demotion failed. Error: $_"
    }

    # Pull Event Log errors after failed demotion
    Get-EventLogErrors -LogName "System"
    Get-EventLogErrors -LogName "Directory Service"

    # Forceful removal of AD DS role
    Write-Log "=== Forcing Removal of AD DS Role ==="
    $addsRole = Get-WindowsFeature -Name AD-Domain-Services
    if ($addsRole.Installed) {
        Write-Log "AD-Domain-Services is installed. Attempting to remove..."
        try {
            $result = Uninstall-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -Remove -Force -ErrorAction Stop
            Write-Log "AD DS role removal result: Success=$($result.Success)"
            if (-not $result.Success) {
                Write-Log "AD DS role removal failed. RestartRequired: $($result.RestartNeeded)"
            }
        }
        catch {
            Write-Log "ERROR: Failed to remove AD DS role. Error: $_"
        }
    }
    else {
        Write-Log "AD-Domain-Services is not installed."
    }

    # Pull Event Log errors after removing AD DS role
    Get-EventLogErrors -LogName "System"
    Get-EventLogErrors -LogName "Directory Service"

    # Remove DNS role
    Write-Log "=== Removing DNS Role ==="
    $dnsRole = Get-WindowsFeature -Name DNS
    if ($dnsRole.Installed) {
        Write-Log "DNS role is installed. Attempting to remove..."
        try {
            $result = Uninstall-WindowsFeature -Name DNS -Remove -Force -ErrorAction Stop
            Write-Log "DNS role removal result: Success=$($result.Success)"
            if (-not $result.Success) {
                Write-Log "DNS role removal failed. RestartRequired: $($result.RestartNeeded)"
            }
        }
        catch {
            Write-Log "ERROR: Failed to remove DNS role. Error: $_"
        }
    }
    else {
        Write-Log "DNS role is not installed."
    }

    # Pull Event Log errors after removing DNS role
    Get-EventLogErrors -LogName "System"
    Get-EventLogErrors -LogName "Directory Service"

    # Unjoin the domain
    Write-Log "=== Unjoining the Domain ==="
    $computer = Get-WmiObject -Class Win32_ComputerSystem
    Write-Log "Current Domain: $($computer.Domain)"
    try {
        Write-Log "Attempting to unjoin domain and join WORKGROUP..."
        $unjoinResult = $computer.UnjoinDomainOrWorkgroup($null, $null, 0)
        Write-Log "Unjoin result: $unjoinResult"
        $joinResult = $computer.JoinDomainOrWorkgroup("WORKGROUP", $null, $null, $null, 0)
        Write-Log "Join WORKGROUP result: $joinResult"
    }
    catch {
        Write-Log "ERROR: Failed to unjoin domain or join WORKGROUP. Error: $_"
        Write-Log "Falling back to manual unjoin via sysdm.cpl..."
        try {
            Start-Process "sysdm.cpl" -ArgumentList ",1" -Wait
            Write-Log "Please manually unjoin the domain and join WORKGROUP using the GUI."
        }
        catch {
            Write-Log "ERROR: Failed to open sysdm.cpl. Error: $_"
        }
    }

    # Pull Event Log errors after unjoining the domain
    Get-EventLogErrors -LogName "System"
    Get-EventLogErrors -LogName "Directory Service"

    # Clean up AD remnants
    Write-Log "=== Cleaning Up AD Remnants ==="
    try {
        Write-Log "Deleting C:\Windows\NTDS..."
        Remove-Item -Path "C:\Windows\NTDS" -Recurse -Force -ErrorAction Stop
        Write-Log "C:\Windows\NTDS deleted successfully."
    }
    catch {
        Write-Log "ERROR: Failed to delete C:\Windows\NTDS. Error: $_"
    }

    try {
        Write-Log "Deleting C:\Windows\SYSVOL..."
        Remove-Item -Path "C:\Windows\SYSVOL" -Recurse -Force -ErrorAction Stop
        Write-Log "C:\Windows\SYSVOL deleted successfully."
    }
    catch {
        Write-Log "ERROR: Failed to delete C:\Windows\SYSVOL. Error: $_"
    }

    # Clean up registry
    Write-Log "Cleaning up registry..."
    try {
        $ntdsReg = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS"
        if (Test-Path $ntdsReg) {
            Write-Log "Removing NTDS registry key..."
            Remove-Item -Path $ntdsReg -Recurse -Force -ErrorAction Stop
            Write-Log "NTDS registry key removed successfully."
        }
        else {
            Write-Log "NTDS registry key not found."
        }
    }
    catch {
        Write-Log "ERROR: Failed to remove NTDS registry key. Error: $_"
    }

    try {
        $computerNameReg = "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName"
        $computerName = (Get-ItemProperty -Path $computerNameReg -Name ComputerName).ComputerName
        Write-Log "Current ComputerName in registry: $computerName"
        if ($computerName -like "*.mlb.dev") {
            Write-Log "ComputerName contains domain suffix. Resetting to machine name only..."
            $machineName = $computerName.Split('.')[0]
            Set-ItemProperty -Path $computerNameReg -Name ComputerName -Value $machineName -ErrorAction Stop
            Write-Log "ComputerName reset to: $machineName"
        }
    }
    catch {
        Write-Log "ERROR: Failed to reset ComputerName in registry. Error: $_"
    }

    # Clear DNS settings
    Write-Log "Clearing DNS settings..."
    try {
        $dnsResult = Start-Process -FilePath "ipconfig" -ArgumentList "/flushdns" -NoNewWindow -Wait -PassThru
        Write-Log "ipconfig /flushdns exit code: $($dnsResult.ExitCode)"
        Stop-Service -Name dnscache -Force -ErrorAction Stop
        Write-Log "DNS cache service stopped."
        Start-Service -Name dnscache -ErrorAction Stop
        Write-Log "DNS cache service started."
    }
    catch {
        Write-Log "ERROR: Failed to clear DNS settings. Error: $_"
    }

    # Pull Event Log errors after cleanup
    Get-EventLogErrors -LogName "System"
    Get-EventLogErrors -LogName "Directory Service"

    # Log final system state
    Write-Log "=== Final System State Before Reboot ==="
    $system = Get-WmiObject -Class Win32_ComputerSystem
    Write-Log "DomainRole: $($system.DomainRole)"
    Write-Log "Domain: $($system.Domain)"
    Write-Log "ComputerName: $($system.Name)"

    $addsRole = Get-WindowsFeature -Name AD-Domain-Services
    Write-Log "AD-Domain-Services Installed: $($addsRole.Installed)"

    $dnsRole = Get-WindowsFeature -Name DNS
    Write-Log "DNS Installed: $($dnsRole.Installed)"

    # Reboot
    Write-Log "Rebooting system to apply changes..."
    Start-Sleep -Seconds 5
    Restart-Computer -Force
}

# Placeholder for other functions (e.g., schema modifications)
function Enable-SchemaModifications {
    Write-Log "🔹 Enabling schema modifications..."
    # Add your existing schema modification logic here
    Write-Log "✅ Schema modifications enabled."
}

# Function to securely get and confirm password
function Get-SecurePassword {
    param(
        [string]$prompt
    )
    while ($true) {
        $password = Read-Host -Prompt $prompt -AsSecureString
        $confirmPassword = Read-Host -Prompt "Confirm password" -AsSecureString
        
        # Convert SecureString to plain text for comparison only
        $BSTR1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
        $BSTR2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmPassword)
        $plainPass1 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR1)
        $plainPass2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR2)
        
        # Clear the pointers immediately
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR1)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR2)

        if ($plainPass1 -eq $plainPass2) {
            Write-Host "Is this your password: $plainPass1 ? (y/n)"
            $confirm = Read-Host
            if ($confirm -eq 'y') {
                # Clear the plain text password from memory
                $plainPass1 = $null
                $plainPass2 = $null
                [System.GC]::Collect()
                return $password
            }
        } else {
            Write-Host "Passwords do not match. Please try again."
        }
        
        # Clear variables
        $plainPass1 = $null
        $plainPass2 = $null
        [System.GC]::Collect()
    }
}

# Function to check for pending reboots
function Test-PendingReboot {
    Write-Log "Checking for pending reboot..."
    $rebootPending = $false
    $reasons = @()

    # Check Component Based Servicing
    $cbsRebootKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    if (Test-Path $cbsRebootKey) {
        $rebootPending = $true
        $reasons += "Component Based Servicing"
    }

    # Check Windows Update
    $wuRebootKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    if (Test-Path $wuRebootKey) {
        $rebootPending = $true
        $reasons += "Windows Update"
    }

    # Check PendingFileRenameOperations
    $pendingRenameKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    if (Get-ItemProperty -Path $pendingRenameKey -Name PendingFileRenameOperations -ErrorAction SilentlyContinue) {
        $rebootPending = $true
        $reasons += "Pending File Rename"
    }

    # Check if a reboot is pending for computer rename
    $activeComputerName = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" -Name "ComputerName").ComputerName
    $pendingComputerName = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName" -Name "ComputerName").ComputerName
    if ($activeComputerName -ne $pendingComputerName) {
        $rebootPending = $true
        $reasons += "Computer Rename"
    }

    if ($rebootPending) {
        $reasonText = $reasons -join ", "
        Write-Log "⚠️ WARNING: System has pending reboot(s) for: $reasonText"
        Write-Host "⚠️ WARNING: System has pending reboot(s) for: $reasonText" -ForegroundColor Yellow
        return $true
    }
    
    Write-Log "No pending reboot detected."
    return $false
}

# Main menu
function Show-Menu {
    # Check for pending reboots first
    $pendingReboot = Test-PendingReboot
    if ($pendingReboot) {
        Write-Host "`n⚠️  SYSTEM REQUIRES REBOOT - Some operations may fail!" -ForegroundColor Red
        Write-Host "    Consider rebooting before proceeding.`n"
    }

    $role = Get-SystemRole
    Write-Host "🖥️  Current System Role: $role"
    Write-Host "1. Install Domain Controller"
    Write-Host "2. Uninstall Domain Controller"
    Write-Host "3. Enable Schema Modifications"
    Write-Host "4. Restore Administrator Profile"
    Write-Host "5. Extend Schema from CSV"
    Write-Host "6. Exit"
    $choice = Read-Host "Enter choice (1-6)"
    return $choice
}

# Main script logic
Write-Log "Starting Flip-42DC.ps1..."
# Check for pending reboots at startup
Test-PendingReboot

while ($true) {
    $choice = Show-Menu
    switch ($choice) {
        "1" {
            if ((Get-SystemRole) -eq "DomainController") {
                Write-Host "❌ System is already a Domain Controller."
                Write-Log "❌ Attempted to install DC, but system is already a DC."
                continue
            }
            $domainName = Read-Host "Enter the FQDN for the new domain (e.g., mlb.dev)"
            $safeModePassword = Get-SecurePassword "Enter the Safe Mode Administrator Password"
            Install-42DomainController -DomainName $domainName -SafeModePassword $safeModePassword
            break
        }
        "2" {
            if ((Get-SystemRole) -ne "DomainController") {
                Write-Host "❌ System is not a Domain Controller."
                Write-Log "❌ Attempted to uninstall DC, but system is not a DC."
                continue
            }
            $localAdminPassword = Get-SecurePassword "Enter the Local Administrator Password"
            Uninstall-42DomainController -LocalAdminPassword $localAdminPassword
            break
        }
        "3" {
            Enable-SchemaModifications
        }
        "4" {
            Restore-42AdminProfile
        }
        "5" {
            $csvPath = Read-Host "Enter the path to the schema CSV file (e.g., data/schema.csv)"
            Extend-SchemaFromCSV -CsvPath $csvPath
        }
        "6" {
            Write-Log "Exiting Flip-42DC.ps1..."
            exit
        }
        default {
            Write-Host "❌ Invalid choice. Please select 1-6."
            Write-Log "❌ Invalid menu choice: $choice"
        }
    }
}