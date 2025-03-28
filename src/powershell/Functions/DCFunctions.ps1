# DCFunctions.ps1

# -------------------------------------------------------------------
# Logging Helper Function
# -------------------------------------------------------------------
function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Message
    )

    $timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    Write-Output $logMessage
    Add-Content -Path $global:LogFile -Value $logMessage
}

# -------------------------------------------------------------------
# Event Log Extraction
# -------------------------------------------------------------------
function Get-EventLogErrors {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$LogName
    )

    Write-Log "=== Extracting Warnings and Errors from $LogName Event Log ==="

    try {
        $events = Get-WinEvent -LogName $LogName -ErrorAction Stop |
            Where-Object { $_.LevelDisplayName -in @("Error", "Warning") } |
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

# -------------------------------------------------------------------
# System Role Check
# -------------------------------------------------------------------
function Get-SystemRole {
    [CmdletBinding()]
    param()

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

# -------------------------------------------------------------------
# Profile Backup and Restore
# -------------------------------------------------------------------
function Backup-42AdminProfile {
    [CmdletBinding()]
    param()

    $profilePath = [System.Environment]::GetFolderPath('UserProfile')
    $backupPath  = "C:\AdminProfileBackup"

    Write-Log "🔹 Backing up Administrator profile from $profilePath to $backupPath..."

    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "ERROR: Must run as Administrator."
        throw "Must run as Administrator."
    }

    if (-not (Test-Path $backupPath)) { New-Item -Path $backupPath -ItemType Directory -Force | Out-Null }

    $drive       = (Get-Item $backupPath).PSDrive
    $freeSpace   = $drive.Free / 1GB
    $sourceSize  = (Get-ChildItem $profilePath -Recurse -ErrorAction Stop | Measure-Object -Property Length -Sum).Sum / 1GB
    if ($freeSpace -lt $sourceSize) {
        Write-Log "ERROR: Insufficient disk space."
        throw "Insufficient disk space."
    }

    try {
        robocopy $profilePath $backupPath /MIR /XJ /B /IT /XF NTUSER.DAT ntuser.dat.LOG1 ntuser.dat.LOG2 /XD "Saved Games" "Searches" "Videos" "AppData\Local\Google" "AppData\Local\Google\Chrome\User Data\BrowserMetrics" /R:3 /W:1 /NP
        $exitCode = $LASTEXITCODE

        $criticalFiles   = @("ntuser.ini")
        $missingCritical = $false
        foreach ($file in $criticalFiles) {
            $destFile = Join-Path $backupPath $file
            if (-not (Test-Path $destFile)) {
                Write-Log "WARNING: Critical file $file not found in backup."
                $missingCritical = $true
            }
        }

        if ($exitCode -le 7) {
            Write-Log "✅ Backup complete (Exit Code: $exitCode)."
        }
        elseif ($exitCode -eq 9 -and -not $missingCritical) {
            Write-Log "⚠️ Backup completed with warnings (Exit Code: $exitCode). Non-critical files failed."
        }
        else {
            Write-Log "ERROR: Backup failed with robocopy exit code $exitCode."
            throw "robocopy failed with exit code $exitCode"
        }
    }
    catch {
        Write-Log "ERROR: Failed to backup Administrator profile. Error: $_"
        throw
    }
}

function Restore-42AdminProfile {
    [CmdletBinding()]
    param()

    $profilePath = [System.Environment]::GetFolderPath('UserProfile')
    $backupPath  = "C:\AdminProfileBackup"

    Write-Log "🔹 Restoring Administrator profile to $profilePath..."

    if (Test-Path $backupPath) {
        try {
            robocopy $backupPath $profilePath /MIR /XJ /R:3 /W:5
            if ($LASTEXITCODE -le 7) {
                Write-Log "✅ Restore complete."
            }
            else {
                Write-Log "ERROR: Restore failed with robocopy exit code $LASTEXITCODE."
                throw "robocopy failed with exit code $LASTEXITCODE"
            }
        }
        catch {
            Write-Log "ERROR: Restore failed. Error: $_"
            throw
        }
    }
    else {
        Write-Log "❌ Backup not found at $backupPath."
    }
}

# -------------------------------------------------------------------
# Domain Controller Installation/Demotion
# -------------------------------------------------------------------
function Install-42DomainController {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName,
        [Parameter(Mandatory)]
        [securestring]$SafeModePassword
    )

    Write-Log "Starting Install-42DomainController for domain: $DomainName..."

    # Test DNS resolution for the domain
    Write-Log "Testing DNS resolution for $DomainName using nslookup..."
    try {
        $dnsResult = nslookup $DomainName 2>&1
        Write-Log "DNS resolution result: $dnsResult"
    }
    catch {
        Write-Log "WARNING: DNS resolution for $DomainName failed. This is expected if creating a new forest. Error: $_"
    }

    # Install AD DS role
    Write-Log "Installing Active Directory Domain Services role..."
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -ErrorAction Stop

    # Promote to Domain Controller (new forest)
    Write-Log "Promoting system to Domain Controller for new forest: $DomainName..."
    Install-ADDSForest `
        -DomainName $DomainName `
        -SafeModeAdministratorPassword $SafeModePassword `
        -InstallDns:$true `
        -Force:$true `
        -ErrorAction Stop

    Write-Log "Domain Controller promotion completed successfully. Reboot required."
    Write-Host "✅ Domain Controller promotion completed. The system will reboot." -ForegroundColor Green
}
function Uninstall-42DomainController {
    [CmdletBinding()]
    param (
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

    # Log AD and DNS role status
    $addsRole = Get-WindowsFeature -Name AD-Domain-Services
    Write-Log "AD-Domain-Services Installed: $($addsRole.Installed)"
    $dnsRole = Get-WindowsFeature -Name DNS
    Write-Log "DNS Installed: $($dnsRole.Installed)"

    # Check for pending reboot
    Write-Log "=== Checking for Pending Reboot ==="
    $rebootReg    = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    $updateReg    = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
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

    # Stop AD DS-related services
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
            -DemoteOperationMasterRole $true `
            -LastDomainControllerInDomain $true `
            -RemoveDnsDelegation $true `
            -RemoveApplicationPartitions $true `
            -IgnoreLastDnsServerForZone $true `
            -Force $true
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

    # Pull Event Log errors after AD DS role removal
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

    # Pull Event Log errors after DNS role removal
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
        $computerName    = (Get-ItemProperty -Path $computerNameReg -Name ComputerName).ComputerName
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

    # Final logs
    Get-EventLogErrors -LogName "System"
    Get-EventLogErrors -LogName "Directory Service"

    Write-Log "=== Final System State Before Reboot ==="
    $system = Get-WmiObject -Class Win32_ComputerSystem
    Write-Log "DomainRole: $($system.DomainRole)"
    Write-Log "Domain: $($system.Domain)"
    Write-Log "ComputerName: $($system.Name)"

    $addsRole = Get-WindowsFeature -Name AD-Domain-Services
    Write-Log "AD-Domain-Services Installed: $($addsRole.Installed)"

    $dnsRole = Get-WindowsFeature -Name DNS
    Write-Log "DNS Installed: $($dnsRole.Installed)"

    Write-Log "Rebooting system to apply changes..."
    Start-Sleep -Seconds 5
    Restart-Computer -Force
}

# -------------------------------------------------------------------
# Additional Functions
# -------------------------------------------------------------------
function Get-SecurePassword {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Prompt
    )

    while ($true) {
        $password        = Read-Host -Prompt $Prompt -AsSecureString
        $confirmPassword = Read-Host -Prompt "Confirm password" -AsSecureString

        $BSTR1     = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
        $BSTR2     = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmPassword)
        $plainPass1 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR1)
        $plainPass2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR2)

        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR1)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR2)

        if ($plainPass1 -eq $plainPass2) {
            Write-Host "Is this your password: $plainPass1 ? (y/n)"
            $confirm = Read-Host
            if ($confirm -eq 'y') {
                $plainPass1 = $null
                $plainPass2 = $null
                [System.GC]::Collect()
                return $password
            }
        }
        else {
            Write-Host "Passwords do not match. Please try again."
        }

        $plainPass1 = $null
        $plainPass2 = $null
        [System.GC]::Collect()
    }
}



